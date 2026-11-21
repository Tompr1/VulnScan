"""
Background job queues (RQ on Redis).

Callers depend on the small protocols below rather than on RQ, so the API
and the worker can be tested with an in-memory queue. Tasks are enqueued by
import path: the API does not need to import the worker module (and, through
it, the 70 scanner plugins) just to enqueue a job.
"""
from __future__ import annotations

from typing import Protocol

from redis import Redis
from redis.exceptions import RedisError
from rq import Queue

from app.core.config import settings

SCAN_TASK = "app.worker_tasks.run_scan_job"
AI_ANALYSIS_TASK = "app.worker_tasks.run_ai_analysis"


class QueueUnavailableError(RuntimeError):
    """The task queue could not accept the job (Redis down or unreachable)."""


class ScanJobQueue(Protocol):
    def enqueue_scan(self, job_id: int) -> None: ...


class AiAnalysisQueue(Protocol):
    def enqueue_ai_analysis(self, analysis_id: int) -> None: ...


class RqJobQueue:
    def __init__(self, redis_url: str, scan_timeout: int, ai_analysis_timeout: int) -> None:
        self._redis_url = redis_url
        self._scan_timeout = scan_timeout
        self._ai_analysis_timeout = ai_analysis_timeout

    def enqueue_scan(self, job_id: int) -> None:
        self._enqueue("scans", SCAN_TASK, job_id, self._scan_timeout)

    def enqueue_ai_analysis(self, analysis_id: int) -> None:
        self._enqueue("ai", AI_ANALYSIS_TASK, analysis_id, self._ai_analysis_timeout)

    def _enqueue(self, queue_name: str, task: str, argument: int, timeout: int) -> None:
        try:
            Queue(queue_name, connection=Redis.from_url(self._redis_url)).enqueue(task, argument, job_timeout=timeout)
        except RedisError as exc:
            raise QueueUnavailableError(str(exc)) from exc


def get_job_queue() -> RqJobQueue:
    """FastAPI dependency and worker factory for the production queue."""
    return RqJobQueue(
        redis_url=settings.REDIS_URL,
        scan_timeout=settings.SCAN_JOB_TIMEOUT,
        ai_analysis_timeout=settings.AI_ANALYSIS_TIMEOUT,
    )
