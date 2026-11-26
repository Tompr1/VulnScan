"""
ScanJobRunner — the scan job use case, from a queued job to saved findings.

A job has two halves joined by two plain messages
(``app.scan_jobs.assignment``):

    1. execution (no database: may run on a probe)
         ScanAssignment -> ScanExecution -> ScanReport

    2. finalization (on the platform)
         ScanReport -> running→processing (once) -> process findings -> save
                    -> publish to graph -> mark done
                    -> announce (generic "scan completed", or the scan type's
                       own announcer: inventory jobs alert on new device issues)
                    -> maybe queue AI analysis

``run`` does both in the platform's worker. ``finalize`` takes a report
produced elsewhere (a probe) for a job already marked running.

Every collaborator is injected; ``app.worker_tasks`` wires the production ones.
"""
from __future__ import annotations

import asyncio
import logging
import traceback
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, Protocol, TypeVar

from app.scan_jobs.ai_trigger import AutoAnalysisTrigger
from app.scan_jobs.assigner import JobAssigner, JobNotReady, VaultFactory
from app.scan_jobs.assignment import ScanReport
from app.scan_jobs.execution import ScanExecution, executor_for
from app.scan_jobs.executors import ScanExecutor
from app.scan_jobs.graph import FindingGraph
from app.scan_jobs.notifications import ScanFailure, ScanNotifier, ScanSummary, build_summary
from app.scan_jobs.outcome import JobCompletion, JobFailure, unknown_scan_type
from app.scan_jobs.processing import FindingProcessor, ProcessedFinding, ProcessingReport
from app.scan_jobs.progress import ThrottledProgressWriter
from app.scan_jobs.repository import ScanJobRepository, ScanJobSnapshot
from app.scanner.profile import ScanProfile
from app.scanner.resources import InMemoryCredentialVault, ReferenceData
from app.scanner.target import ScanType

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

ProcessorFactory = Callable[[ScanJobSnapshot, ScanProfile], FindingProcessor]


class CompletionAnnouncer(Protocol):
    def announce(self, job: ScanJobSnapshot, findings: Sequence[ProcessedFinding], summary: ScanSummary) -> Any:
        """Tell the workspace about a finished job (instead of "scan completed")."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanJobRunner:
    def __init__(
        self,
        repository: ScanJobRepository,
        executors: Mapping[ScanType, ScanExecutor],
        processor_factory: ProcessorFactory,
        notifier: ScanNotifier,
        graph_factory: Callable[[], FindingGraph],
        ai_trigger: AutoAnalysisTrigger,
        clock: Callable[[], datetime] = _utc_now,
        announcers: Mapping[ScanType, CompletionAnnouncer] | None = None,
        credentials: VaultFactory | None = None,
        reference: ReferenceData | None = None,
    ) -> None:
        self._repository = repository
        self._executors = executors
        self._execution = ScanExecution(executors, reference)
        self._processor_factory = processor_factory
        self._notifier = notifier
        self._graph_factory = graph_factory
        self._ai_trigger = ai_trigger
        self._clock = clock
        self._announcers = dict(announcers or {})
        self._assigner = JobAssigner(repository, credentials or (lambda _workspace_id: InMemoryCredentialVault()))

    # ── Use cases ────────────────────────────────────────────────────────

    def run(self, job_id: int) -> None:
        """Execute and finalize a queued job in this worker."""
        job = self._repository.load_job(job_id)
        if job is None:
            logger.error("Job #%d not found", job_id)
            return
        self._guarded(job, lambda: self._run(job))

    def finalize(self, job_id: int, report: ScanReport) -> bool:
        """Finalize a job with a report produced elsewhere.

        Returns False when the report was not used: unknown job, report for
        another job, or job no longer running (results already received).
        """
        if report.job_id != job_id:
            logger.error("Report for job #%d delivered to job #%d: ignored", report.job_id, job_id)
            return False
        job = self._repository.load_job(job_id)
        if job is None:
            logger.error("Job #%d not found: report ignored", job_id)
            return False
        return bool(self._guarded(job, lambda: self._finalize(job, self._profile_after_scan(job), report)))

    # ── Steps ────────────────────────────────────────────────────────────

    def _run(self, job: ScanJobSnapshot) -> None:
        profile = self._profile_for(job)
        assignment = self._assigner.assignment_for(job, profile)
        self._repository.mark_running(job.id, self._clock())
        logger.info("Starting scan job #%d target=%s type=%s", job.id, job.target, job.scan_type)
        progress = ThrottledProgressWriter(lambda document: self._repository.write_progress(job.id, document))
        report = asyncio.run(self._execution.execute(assignment, progress))
        self._finalize(job, profile, report)

    def _guarded(self, job: ScanJobSnapshot, step: Callable[[], _T]) -> _T | None:
        try:
            return step()
        except JobNotReady as unready:
            self._fail(job, unready.failure)
        except Exception as exc:  # last resort: a job must never stay "running"
            logger.exception("Unhandled error in scan job #%d", job.id)
            self._fail(job, JobFailure(
                error=str(exc),
                error_type="unhandled",
                detail=f"An unexpected error occurred during scan processing.\n\nTechnical detail: {str(exc)[:500]}",
                traceback=traceback.format_exc(),
            ))
        finally:
            self._delete_ephemeral_credential(job)
        return None

    def _finalize(self, job: ScanJobSnapshot, profile: ScanProfile, report: ScanReport) -> bool:
        # A report, success or failure, is accepted once and only for a
        # running job: a second delivery, or a report for a job the watchdog
        # already failed, changes nothing.
        if not self._repository.start_processing(job.id):
            logger.warning("Job #%d is not running anymore: its report is ignored", job.id)
            return False
        if report.failure is not None:
            self._fail(job, report.failure)
            return True

        processor = self._processor_factory(job, profile)
        processed = processor.process(list(report.findings), job.target, self._repository.suppressed_fingerprints(job.workspace_id))
        self._repository.save_findings(job, processed.saved)
        self._publish_to_graph(job, processed)

        finished_at = self._clock()
        self._repository.mark_done(job.id, JobCompletion(
            findings_total=processed.total,
            findings_saved=len(processed.saved),
            findings_dropped=processed.dropped,
            min_confidence_threshold=processor.min_confidence,
        ), finished_at)
        logger.info("Job #%d done: %d saved, %d dropped of %d", job.id, len(processed.saved), processed.dropped, processed.total)

        summary = build_summary(
            job.id, job.target, job.scan_type, processed.saved, processed.severity_counts(), job.created_at, finished_at,
        )
        announcer = self._announcers.get(ScanType.parse(job.scan_type))
        if announcer is None:
            self._notifier.scan_completed(job.workspace_id, summary)
        else:
            self._announce(announcer, job, processed.saved, summary)
        if self._executor_for(job).ai_analysis:
            self._queue_ai_analysis(job, len(processed.saved))
        return True

    def _executor_for(self, job: ScanJobSnapshot) -> ScanExecutor:
        executor = executor_for(self._executors, job.scan_type)
        if executor is None:
            raise JobNotReady(unknown_scan_type(job.scan_type))
        return executor

    def _profile_for(self, job: ScanJobSnapshot) -> ScanProfile:
        self._executor_for(job)  # a type this platform cannot run fails first
        return self._assigner.profile_for(job)

    def _profile_after_scan(self, job: ScanJobSnapshot) -> ScanProfile:
        """The profile used to process findings that arrive after the scan:
        one deleted in the meantime must not cost the results."""
        try:
            return self._profile_for(job)
        except JobNotReady:
            self._executor_for(job)  # an unknown scan type still fails the job
            logger.warning("Profile of job #%d is gone: its findings are processed with defaults", job.id)
            return ScanProfile().with_web_auth(job.web_auth)

    def _publish_to_graph(self, job: ScanJobSnapshot, report: ProcessingReport) -> None:
        graph = self._graph_factory()
        try:
            for finding in report.saved:
                try:
                    graph.record(job.workspace_id, job.target, finding)
                except Exception as exc:  # the graph is an optional view of the findings
                    logger.debug("Graph upsert failed for %s: %s", finding.fingerprint, exc)
        finally:
            graph.close()

    @staticmethod
    def _announce(
        announcer: CompletionAnnouncer, job: ScanJobSnapshot, saved: Sequence[ProcessedFinding], summary: ScanSummary
    ) -> None:
        try:
            announcer.announce(job, saved, summary)
        except Exception as exc:  # the job itself succeeded: an alert failure must not fail it
            logger.warning("Completion announcement failed for job #%d: %s", job.id, exc)

    def _queue_ai_analysis(self, job: ScanJobSnapshot, saved_findings: int) -> None:
        try:
            if self._ai_trigger.maybe_queue(job.id, job.workspace_id, saved_findings):
                self._repository.mark_analyzing(job.id)
        except Exception as exc:  # the scan itself succeeded: never fail it here
            logger.warning("Auto AI analysis failed to queue for job #%d: %s", job.id, exc)

    def _fail(self, job: ScanJobSnapshot, failure: JobFailure) -> None:
        try:
            self._repository.mark_failed(job.id, failure, self._clock())
        except Exception as exc:  # nothing left to try: make it visible in the logs
            logger.critical("Job #%d could not be marked as failed and may be stuck: %s", job.id, exc)
            return
        self._notifier.scan_failed(job.workspace_id, ScanFailure(job.id, job.target, failure.error, failure.error_type))

    def _delete_ephemeral_credential(self, job: ScanJobSnapshot) -> None:
        try:
            self._repository.delete_ephemeral_credential(job)
        except Exception as exc:  # cleanup is best effort and must not hide the scan outcome
            logger.warning("Ephemeral credential cleanup failed for job #%d: %s", job.id, exc)
