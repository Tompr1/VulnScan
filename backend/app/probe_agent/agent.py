"""
ProbeAgent — runs the client's jobs the platform hands to this probe.

    loop:
      send the reports still waiting on disk
      wait for a job (long poll)
      check it against the probe's own scope (local allowlist)
      run it with ScanExecution, the same code as the platform's worker,
        sending progress; the platform's answer may say "stop"
      keep the report on disk, send it, delete it once accepted

One job at a time. Credentials come with the job and stay in memory; only
reports (findings, no secrets) are written to disk, readable by the probe's
user only, so a restart or a network cut does not lose a finished scan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from app.probe_agent.platform import JobGone, MessageRefused, PlatformClient, PlatformUnavailable, ProbeRejected
from app.probe_agent.reference import RemoteReferenceData
from app.scan_jobs.assignment import ScanAssignment, ScanReport
from app.scan_jobs.execution import ScanExecution
from app.scan_jobs.executors import ScanExecutor
from app.scan_jobs.outcome import JobFailure
from app.scan_jobs.progress import ThrottledProgressWriter
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.target import InvalidTargetError, ScanTarget, ScanType

logger = logging.getLogger(__name__)

# Builds the executors of one job from its allowlist and its stop signal.
ExecutorsFactory = Callable[[AllowlistPolicy, "RemoteCancellation"], Mapping[ScanType, ScanExecutor]]

_RETRY_DELAYS = (5, 10, 30, 60)


class RemoteProgress:
    """Progress writer of one job: posts each document to the platform and
    remembers when it answered "stop" (or the job is no longer ours)."""

    def __init__(self, client: PlatformClient, job_id: int) -> None:
        self._client = client
        self._job_id = job_id
        self.stop_requested = False

    def write(self, document_json: str) -> None:
        try:
            if self._client.progress(self._job_id, json.loads(document_json)):
                self.stop_requested = True
        except (JobGone, ProbeRejected) as exc:
            logger.warning("Job #%d is no longer this probe's (%s): stopping it", self._job_id, exc)
            self.stop_requested = True
        except (PlatformUnavailable, MessageRefused) as exc:
            # Progress is informative: the scan goes on without it.
            logger.warning("Progress of job #%d not sent: %s", self._job_id, exc)


class RemoteCancellation:
    """The engine's stop signal, raised by the platform's progress answers."""

    def __init__(self, progress: RemoteProgress) -> None:
        self._progress = progress

    def request(self, job_id: int) -> None:
        self._progress.stop_requested = True

    def consume(self, job_id: int) -> bool:
        stop, self._progress.stop_requested = self._progress.stop_requested, False
        return stop


class FixedAllowlist:
    """AllowlistSource answering one policy, the job's."""

    def __init__(self, policy: AllowlistPolicy) -> None:
        self._policy = policy

    def policy_for(self, workspace_id: int) -> AllowlistPolicy:
        return self._policy


class ReportOutbox:
    """Reports waiting to be accepted by the platform, one file per job."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def put(self, report: ScanReport) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._path(report.job_id)
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(report.to_dict(), out)
        os.replace(temporary, path)

    def pending(self) -> list[ScanReport]:
        if not self._directory.is_dir():
            return []
        reports = []
        for path in sorted(self._directory.glob("job-*.json")):
            try:
                reports.append(ScanReport.from_dict(json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                logger.error("Unreadable pending report %s, set aside: %s", path.name, exc)
                path.rename(path.with_suffix(".unreadable"))
        return reports

    def remove(self, job_id: int) -> None:
        self._path(job_id).unlink(missing_ok=True)

    def _path(self, job_id: int) -> Path:
        return self._directory / f"job-{int(job_id)}.json"


class ProbeAgent:
    def __init__(
        self,
        client: PlatformClient,
        reference: RemoteReferenceData,
        executors: ExecutorsFactory,
        outbox: ReportOutbox,
        local_allowlist: str | None = None,
        wait_seconds: int = 25,
        sleep: Callable[[float], Any] = asyncio.sleep,
        keepalive_seconds: float = 60.0,
    ) -> None:
        self._client = client
        self._reference = reference
        self._executors = executors
        self._outbox = outbox
        self._local = AllowlistPolicy.from_setting(local_allowlist) if local_allowlist else None
        self._wait = wait_seconds
        self._sleep = sleep
        self._keepalive_seconds = keepalive_seconds

    async def run_forever(self, should_stop: Callable[[], bool] = lambda: False) -> None:
        """Until stopped, or until the platform rejects the probe
        (:class:`ProbeRejected` is raised: a human must act)."""
        failures = 0
        while not should_stop():
            try:
                await self.run_once()
                failures = 0
            except PlatformUnavailable as exc:
                delay = _RETRY_DELAYS[min(failures, len(_RETRY_DELAYS) - 1)]
                failures += 1
                logger.warning("Platform unreachable (%s): retrying in %ds", exc, delay)
                await self._sleep(delay)

    async def run_once(self) -> bool:
        """Sends waiting reports, then runs one job if there is one.
        Returns whether a job was run."""
        await asyncio.to_thread(self.flush_outbox)
        assignment = await asyncio.to_thread(self._client.next_job, self._wait)
        if assignment is None:
            return False
        logger.info("Job #%d: %s scan of %s", assignment.job_id, assignment.scan_type, assignment.target)
        report = await self.execute(assignment)
        self._outbox.put(report)
        await asyncio.to_thread(self.flush_outbox)
        return True

    async def execute(self, assignment: ScanAssignment) -> ScanReport:
        refused = self._refusal(assignment)
        if refused is not None:
            logger.warning("Job #%d refused: %s", assignment.job_id, refused.error)
            return ScanReport.failed(assignment.job_id, refused)
        await asyncio.to_thread(self._reference.refresh)
        progress = RemoteProgress(self._client, assignment.job_id)
        executors = self._executors(AllowlistPolicy.from_setting(assignment.allowlist), RemoteCancellation(progress))
        execution = ScanExecution(executors, self._reference)
        # A plugin may run for minutes without progress: keep the probe shown online.
        keepalive = asyncio.create_task(self._keep_alive())
        try:
            report = await execution.execute(assignment, ThrottledProgressWriter(progress.write))
        finally:
            keepalive.cancel()
        logger.info("Job #%d finished: %s", assignment.job_id,
                    f"failed ({report.failure.error})" if report.failure else f"{len(report.findings)} findings")
        return report

    async def _keep_alive(self) -> None:
        while True:
            await asyncio.sleep(self._keepalive_seconds)
            try:
                await asyncio.to_thread(self._client.heartbeat)
            except Exception as exc:  # the scan goes on; the next call says more
                logger.warning("Heartbeat failed: %s", exc)

    def flush_outbox(self) -> None:
        """Sends the waiting reports. A report the platform will never take
        (job gone, refused) is dropped; on a network error the rest waits."""
        for report in self._outbox.pending():
            try:
                self._client.report(report.job_id, report)
            except (JobGone, MessageRefused) as exc:
                logger.warning("Report of job #%d dropped by the platform: %s", report.job_id, exc)
            self._outbox.remove(report.job_id)

    def _refusal(self, assignment: ScanAssignment) -> JobFailure | None:
        if assignment.allowlist is None:
            return JobFailure(
                error="Job without allowlist",
                error_type="configuration",
                detail="The platform sent no allowlist for this job: a probe never scans without one.",
            )
        if self._local is None:
            return None
        try:
            target = ScanTarget.parse(assignment.target)
            scan_type = ScanType.parse(assignment.scan_type)
        except (InvalidTargetError, ValueError):
            return None  # the executor reports an unusable target or type itself
        if self._local.allows(target, scan_type):
            return None
        return JobFailure(
            error="Target outside this probe's scope",
            error_type="configuration",
            detail=(
                f"'{assignment.target}' is outside the scope the client set on its probe "
                f"(local allowlist: {self._local}). Ask the client to widen it, or scan from the platform."
            ),
        )
