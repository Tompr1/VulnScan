"""
ScanJobRunner — the scan job use case, from a queued job to saved findings.

    load job → resolve profile → mark running → execute scan
             → process findings → save → publish to graph → mark done
             → notify → maybe queue AI analysis

Every collaborator is injected; ``app.worker_tasks`` wires the production ones.
"""
from __future__ import annotations

import asyncio
import logging
import traceback
from collections.abc import Callable, Mapping
from datetime import datetime, timezone

from app.scan_jobs.ai_trigger import AutoAnalysisTrigger
from app.scan_jobs.executors import ScanExecutor
from app.scan_jobs.graph import FindingGraph
from app.scan_jobs.notifications import ScanFailure, ScanNotifier, build_summary
from app.scan_jobs.processing import FindingProcessor, ProcessingReport
from app.scan_jobs.progress import ThrottledProgressWriter
from app.scan_jobs.repository import JobCompletion, JobFailure, ScanJobRepository, ScanJobSnapshot
from app.scanner.profile import ScanProfile
from app.scanner.target import ScanType

logger = logging.getLogger(__name__)

ProcessorFactory = Callable[[ScanJobSnapshot, ScanProfile], FindingProcessor]


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
    ) -> None:
        self._repository = repository
        self._executors = executors
        self._processor_factory = processor_factory
        self._notifier = notifier
        self._graph_factory = graph_factory
        self._ai_trigger = ai_trigger
        self._clock = clock

    def run(self, job_id: int) -> None:
        job = self._repository.load_job(job_id)
        if job is None:
            logger.error("Job #%d not found", job_id)
            return
        try:
            self._run(job)
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

    def _run(self, job: ScanJobSnapshot) -> None:
        executor = self._executor_for(job)
        if executor is None:
            self._fail(job, JobFailure(
                error=f"Unknown scan type: {job.scan_type}",
                error_type="configuration",
            ))
            return

        profile = self._profile_for(job, executor)
        if profile is None:
            self._fail(job, JobFailure(
                error="Profile not found",
                error_type="configuration",
                detail=(
                    f"Profile ID {job.profile_id} does not exist in workspace {job.workspace_id}. "
                    "Create a scan profile first under Configuration -> Profiles."
                ),
            ))
            return

        self._repository.mark_running(job.id, self._clock())
        logger.info("Starting scan job #%d target=%s type=%s", job.id, job.target, job.scan_type)
        progress = ThrottledProgressWriter(lambda document: self._repository.write_progress(job.id, document))
        try:
            findings = asyncio.run(executor.execute(job, profile, progress))
        except Exception as exc:  # any scanner failure is reported on the job
            logger.exception("Scan failed for job #%d", job.id)
            self._fail(job, JobFailure(
                error=str(exc),
                error_type="scan_engine",
                detail=(
                    f"The scan engine encountered an error while scanning '{job.target}'. "
                    "This may be caused by: network unreachable, DNS resolution failure, "
                    "target refused connection, or a plugin crash.\n\n"
                    f"Technical detail: {str(exc)[:500]}"
                ),
                traceback=traceback.format_exc(),
            ))
            return

        processor = self._processor_factory(job, profile)
        report = processor.process(findings, job.target, self._repository.suppressed_fingerprints(job.workspace_id))
        self._repository.save_findings(job, report.saved)
        self._publish_to_graph(job, report)

        finished_at = self._clock()
        self._repository.mark_done(job.id, JobCompletion(
            findings_total=report.total,
            findings_saved=len(report.saved),
            findings_dropped=report.dropped,
            min_confidence_threshold=processor.min_confidence,
        ), finished_at)
        logger.info("Job #%d done: %d saved, %d dropped of %d", job.id, len(report.saved), report.dropped, report.total)

        self._notifier.scan_completed(job.workspace_id, build_summary(
            job.id, job.target, job.scan_type, report.saved, report.severity_counts(), job.created_at, finished_at,
        ))
        self._queue_ai_analysis(job, len(report.saved))

    def _executor_for(self, job: ScanJobSnapshot) -> ScanExecutor | None:
        try:
            return self._executors.get(ScanType.parse(job.scan_type))
        except ValueError:
            return None

    def _profile_for(self, job: ScanJobSnapshot, executor: ScanExecutor) -> ScanProfile | None:
        profile = (
            self._repository.load_profile(job.workspace_id, job.profile_id)
            if executor.requires_profile
            else ScanProfile()
        )
        return profile.with_web_auth(job.web_auth) if profile else None

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
