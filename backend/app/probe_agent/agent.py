"""
ProbeAgent — runs the client's jobs the platform hands to this probe.

    loop:
      send the reports still waiting on disk
      wait for a job (long poll): a scan, or a host discovery
      check it against the probe's own scope (local allowlist)
      run it — a scan with ScanExecution, the same code as the platform's
        worker; a discovery with app.core.host_discovery — sending progress;
        the platform's answer may say "stop"
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
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from app.core.host_discovery import NotPrivateNetworkError, discover_hosts, parse_private_network
from app.discovery.assignment import CANCELLED, DONE, FAILED, DiscoveryAssignment, DiscoveryReport
from app.probe_agent.platform import JobGone, MessageRefused, PlatformClient, PlatformUnavailable, ProbeRejected
from app.probe_agent.reference import RemoteReferenceData
from app.scan_jobs.assignment import ScanAssignment, ScanReport
from app.scan_jobs.execution import ScanExecution
from app.scan_jobs.executors import ScanExecutor
from app.scan_jobs.outcome import JobFailure
from app.scan_jobs.progress import ThrottledProgressWriter
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.target import InvalidTargetError, ScanType

logger = logging.getLogger(__name__)

# Builds the executors of one job from its allowlist and its stop signal.
ExecutorsFactory = Callable[[AllowlistPolicy, "RemoteCancellation"], Mapping[ScanType, ScanExecutor]]
# app.core.host_discovery.discover_hosts, or a stand-in in tests.
Discover = Callable[..., list[dict]]
Report = ScanReport | DiscoveryReport

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
    """Reports waiting to be accepted by the platform, one file per job
    (``job-<id>.json``) or per discovery (``discovery-<id>.json``)."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def put(self, report: Report) -> None:
        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._path_of(report)
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(report.to_dict(), out)
        os.replace(temporary, path)

    def pending(self) -> list[Report]:
        if not self._directory.is_dir():
            return []
        reports: list[Report] = []
        for pattern, kind in (("job-*.json", ScanReport), ("discovery-*.json", DiscoveryReport)):
            for path in sorted(self._directory.glob(pattern)):
                try:
                    reports.append(kind.from_dict(json.loads(path.read_text(encoding="utf-8"))))
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    logger.error("Unreadable pending report %s, set aside: %s", path.name, exc)
                    path.rename(path.with_suffix(".unreadable"))
        return reports

    def remove(self, job_id: int) -> None:
        self._path(job_id).unlink(missing_ok=True)

    def discard(self, report: Report) -> None:
        self._path_of(report).unlink(missing_ok=True)

    def _path(self, job_id: int) -> Path:
        return self._directory / f"job-{int(job_id)}.json"

    def _path_of(self, report: Report) -> Path:
        if isinstance(report, DiscoveryReport):
            return self._directory / f"discovery-{int(report.discovery_id)}.json"
        return self._path(report.job_id)


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
        discover: Discover = discover_hosts,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._reference = reference
        self._executors = executors
        self._outbox = outbox
        self._local = AllowlistPolicy.from_setting(local_allowlist) if local_allowlist else None
        self._wait = wait_seconds
        self._sleep = sleep
        self._keepalive_seconds = keepalive_seconds
        self._discover = discover
        self._clock = clock

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
        if isinstance(assignment, DiscoveryAssignment):
            logger.info("Discovery #%d of %s", assignment.discovery_id, assignment.network_range)
            report = await self.discover(assignment)
        else:
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

    async def discover(self, assignment: DiscoveryAssignment) -> DiscoveryReport:
        """Discovers the live hosts of the range, wave by wave, posting what
        it found after each wave. Stops when the platform says so or at the
        time budget, keeping the hosts found."""
        refused = self._discovery_refusal(assignment)
        if refused is not None:
            logger.warning("Discovery #%d refused: %s", assignment.discovery_id, refused)
            return DiscoveryReport(assignment.discovery_id, FAILED, 0, [], refused)

        discovery_id = assignment.discovery_id
        deadline = self._clock() + assignment.budget_seconds
        state = {"probed": 0, "hosts": [], "stop": False, "out_of_time": False}

        def on_progress(probed: int, hosts: list[dict]) -> None:
            state["probed"], state["hosts"] = probed, hosts
            try:
                if self._client.discovery_progress(discovery_id, probed, hosts):
                    state["stop"] = True
            except (JobGone, ProbeRejected) as exc:
                logger.warning("Discovery #%d is no longer this probe's (%s): stopping it", discovery_id, exc)
                state["stop"] = True
            except (PlatformUnavailable, MessageRefused) as exc:
                logger.warning("Progress of discovery #%d not sent: %s", discovery_id, exc)

        def should_stop() -> bool:
            if self._clock() >= deadline:
                state["out_of_time"] = True
            return state["stop"] or state["out_of_time"]

        keepalive = asyncio.create_task(self._keep_alive())
        try:
            hosts = await asyncio.to_thread(
                self._discover, assignment.network, on_progress=on_progress, should_stop=should_stop,
            )
        except Exception as exc:  # noqa: BLE001 — the platform must hear about it
            logger.exception("Discovery #%d failed", discovery_id)
            return DiscoveryReport(discovery_id, FAILED, state["probed"], state["hosts"], f"Discovery failed on the probe: {exc}")
        finally:
            keepalive.cancel()

        if state["out_of_time"]:
            minutes = max(1, assignment.budget_seconds // 60)
            return DiscoveryReport(discovery_id, FAILED, state["probed"], hosts, (
                f"Stopped after its time budget ({minutes} min). The hosts found so far are kept; "
                "discover a smaller range to cover the rest."
            ))
        status = CANCELLED if state["stop"] else DONE
        logger.info("Discovery #%d %s: %d host(s)", discovery_id, status, len(hosts))
        return DiscoveryReport(discovery_id, status, state["probed"], hosts)

    def _discovery_refusal(self, assignment: DiscoveryAssignment) -> str | None:
        """Why this probe will not probe the range, or None."""
        if assignment.allowlist is None:
            return "The platform sent no allowlist for this discovery: a probe never probes without one."
        try:
            network = parse_private_network(assignment.network_range)
        except (NotPrivateNetworkError, ValueError) as exc:
            return f"Refused range {assignment.network_range}: {exc}"
        policy = AllowlistPolicy.from_setting(assignment.allowlist)
        if not policy.allows_network(network):
            return f"{network} is outside the client's allowlist ({policy})."
        if self._local is not None and not self._local.allows_network(network):
            return (
                f"{network} is outside the scope the client set on its probe (local allowlist: {self._local}). "
                "Ask the client to widen it."
            )
        return None

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
                if isinstance(report, DiscoveryReport):
                    self._client.discovery_report(report)
                else:
                    self._client.report(report.job_id, report)
            except (JobGone, MessageRefused) as exc:
                logger.warning("Report %s dropped by the platform: %s", _name(report), exc)
            self._outbox.discard(report)

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
            scan_type = ScanType.parse(assignment.scan_type)
            if self._local.allows_target(assignment.target, scan_type):
                return None
        except (InvalidTargetError, ValueError):
            return None  # the executor reports an unusable target or type itself
        return JobFailure(
            error="Target outside this probe's scope",
            error_type="configuration",
            detail=(
                f"'{assignment.target}' is outside the scope the client set on its probe "
                f"(local allowlist: {self._local}). Ask the client to widen it."
            ),
        )


def _name(report: Report) -> str:
    if isinstance(report, DiscoveryReport):
        return f"of discovery #{report.discovery_id}"
    return f"of job #{report.job_id}"
