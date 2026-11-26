"""
ScanExecution — runs one assignment and reports what it found.

    assignment -> executor of its scan type -> raw findings -> report

This is the part of a scan job that can run away from the platform: it needs
neither the database nor the platform's secret key. Credentials come with
the assignment; the reference data (CVE catalog, KEV…) is given to it. The
platform's worker uses it today; a probe will use it unchanged.

Every failure becomes a failed report: what to do with it (mark the job
failed, notify) is the platform's business.
"""
from __future__ import annotations

import logging
import traceback
from collections.abc import Mapping

from app.scan_jobs.assignment import ScanAssignment, ScanReport
from app.scan_jobs.executors import ScanExecutor
from app.scan_jobs.outcome import JobFailure
from app.scanner.engine import ProgressCallback
from app.scanner.resources import InMemoryReferenceData, ReferenceData, ScanResources
from app.scanner.target import ScanType

logger = logging.getLogger(__name__)


def unknown_scan_type(scan_type: str) -> JobFailure:
    return JobFailure(error=f"Unknown scan type: {scan_type}", error_type="configuration")


def executor_for(executors: Mapping[ScanType, ScanExecutor], scan_type: str) -> ScanExecutor | None:
    try:
        return executors.get(ScanType.parse(scan_type))
    except ValueError:
        return None


class ScanExecution:
    def __init__(
        self,
        executors: Mapping[ScanType, ScanExecutor],
        reference: ReferenceData | None = None,
    ) -> None:
        self._executors = executors
        self._reference = reference or InMemoryReferenceData()

    async def execute(self, assignment: ScanAssignment, progress: ProgressCallback) -> ScanReport:
        executor = executor_for(self._executors, assignment.scan_type)
        if executor is None:
            return ScanReport.failed(assignment.job_id, unknown_scan_type(assignment.scan_type))
        resources = ScanResources(assignment.credential_vault(), self._reference)
        try:
            findings = await executor.execute(assignment, resources, progress)
        except Exception as exc:  # any scanner failure is reported on the job
            logger.exception("Scan failed for job #%d", assignment.job_id)
            return ScanReport.failed(assignment.job_id, JobFailure(
                error=str(exc),
                error_type="scan_engine",
                detail=(
                    f"The scan engine encountered an error while scanning '{assignment.target}'. "
                    "This may be caused by: network unreachable, DNS resolution failure, "
                    "target refused connection, or a plugin crash.\n\n"
                    f"Technical detail: {str(exc)[:500]}"
                ),
                traceback=traceback.format_exc(),
            ))
        return ScanReport.succeeded(assignment.job_id, findings)
