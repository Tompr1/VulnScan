"""
Background job queues (RQ on Redis).

Callers depend on the small protocols below rather than on RQ, so the API
and the worker can be tested with an in-memory queue. Tasks are enqueued by
import path: the API does not need to import the worker module (and, through
it, the 70 scanner plugins) just to enqueue a job.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Protocol

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue

from app.core.config import settings

logger = logging.getLogger(__name__)

SCAN_TASK = "app.worker_tasks.run_scan_job"
REPORT_TASK = "app.worker_tasks.finalize_scan_report"
AI_ANALYSIS_TASK = "app.worker_tasks.run_ai_analysis"
CVE_CATALOG_SYNC_TASK = "app.worker_tasks.run_cve_catalog_sync"
# Above the sync's own time budget (NvdCatalogSync.budget_seconds), so a run
# always stops by itself and saves its progress before RQ would kill it.
CVE_CATALOG_SYNC_TIMEOUT = 7200


class QueueUnavailableError(RuntimeError):
    """The task queue could not accept the job (Redis down or unreachable)."""


class ScanJobQueue(Protocol):
    def enqueue_scan(self, job_id: int) -> None: ...


class ScanReportQueue(Protocol):
    def enqueue_report(self, job_id: int, report: dict[str, Any]) -> None:
        """Finalize in a worker the report a probe sent for this job."""


class AiAnalysisQueue(Protocol):
    def enqueue_ai_analysis(self, analysis_id: int) -> None: ...


class CveCatalogSyncQueue(Protocol):
    def enqueue_cve_catalog_sync(self) -> None: ...


class RqJobQueue:
    def __init__(self, redis_url: str, scan_timeout: int, ai_analysis_timeout: int) -> None:
        self._redis_url = redis_url
        self._scan_timeout = scan_timeout
        self._ai_analysis_timeout = ai_analysis_timeout

    def enqueue_scan(self, job_id: int) -> None:
        self._enqueue("scans", SCAN_TASK, job_id, self._scan_timeout)

    def enqueue_report(self, job_id: int, report: dict[str, Any]) -> None:
        # Saving the findings of a report is the end of a scan job: same budget.
        self._enqueue("scans", REPORT_TASK, job_id, self._scan_timeout, report)

    def enqueue_ai_analysis(self, analysis_id: int) -> None:
        self._enqueue("ai", AI_ANALYSIS_TASK, analysis_id, self._ai_analysis_timeout)

    def enqueue_cve_catalog_sync(self) -> None:
        self._enqueue("datasets", CVE_CATALOG_SYNC_TASK, None, CVE_CATALOG_SYNC_TIMEOUT)

    def _enqueue(self, queue_name: str, task: str, argument: int | None, timeout: int, *more: Any) -> None:
        arguments = (() if argument is None else (argument,)) + more
        try:
            Queue(queue_name, connection=Redis.from_url(self._redis_url)).enqueue(task, *arguments, job_timeout=timeout)
        except RedisError as exc:
            raise QueueUnavailableError(str(exc)) from exc


class ProbeAwareJobQueue:
    """Hands a scan job to the queue of the platform's workers, unless the
    client runs that scan type on its probe: the job then stays queued,
    marked for the probe, which claims it (``app.probes.jobs``).

    Every place that creates a scan job enqueues it here, so they all follow
    the client's choice without knowing about probes."""

    def __init__(self, session_factory: Callable[[], Any], platform: RqJobQueue) -> None:
        self._session_factory = session_factory
        self._platform = platform

    def enqueue_scan(self, job_id: int) -> None:
        import json
        from datetime import datetime, timezone

        from app.db import models
        from app.probes.placement import PROBE, placement_of
        from app.scan_jobs import network_scope

        with self._session_factory() as db:
            job = db.get(models.ScanJob, job_id)
            if job is not None and network_scope.requires_probe(job.scan_type):
                # Scheduled scans and re-verifications reach here without the
                # submission's check: an internal scan never falls back to the
                # platform, it fails with the reason.
                now = datetime.now(timezone.utc)
                try:
                    network_scope.check_scan(db, job.workspace_id, job.scan_type, job.target, now)
                except network_scope.NetworkScanRefused as refused:
                    try:
                        meta = json.loads(job.meta_json) if job.meta_json else {}
                    except ValueError:
                        meta = {}
                    if not isinstance(meta, dict):
                        meta = {}
                    meta.update({"error": refused.message, "error_type": "configuration", "error_detail": refused.message})
                    job.status = "failed"
                    job.finished_at = now
                    job.meta_json = json.dumps(meta)
                    db.commit()
                    logger.info("Scan job #%d refused: %s", job_id, refused.message)
                    return
            if job is not None and placement_of(db, job.workspace_id, job.scan_type) == PROBE:
                job.runs_on = PROBE
                db.commit()
                logger.info("Scan job #%d waits for a probe of client #%d", job_id, job.workspace_id)
                return
        self._platform.enqueue_scan(job_id)

    def enqueue_report(self, job_id: int, report: dict[str, Any]) -> None:
        self._platform.enqueue_report(job_id, report)

    def enqueue_ai_analysis(self, analysis_id: int) -> None:
        self._platform.enqueue_ai_analysis(analysis_id)

    def enqueue_cve_catalog_sync(self) -> None:
        self._platform.enqueue_cve_catalog_sync()


def get_job_queue() -> ProbeAwareJobQueue:
    """FastAPI dependency and worker factory for the production queue."""
    from app.db.session import SessionLocal

    return ProbeAwareJobQueue(SessionLocal, RqJobQueue(
        redis_url=settings.REDIS_URL,
        scan_timeout=settings.SCAN_JOB_TIMEOUT,
        ai_analysis_timeout=settings.AI_ANALYSIS_TIMEOUT,
    ))
