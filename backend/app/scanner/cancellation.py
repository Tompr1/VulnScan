"""
Scan cancellation signal shared by the API (which requests a cancel) and the
scan engine (which checks it between plugins).
"""
from __future__ import annotations

import logging
from typing import Protocol

from redis import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class CancellationSignal(Protocol):
    def request(self, job_id: int) -> None:
        """Ask the running scan of ``job_id`` to stop."""

    def consume(self, job_id: int) -> bool:
        """True (once) if a cancel was requested for ``job_id``."""


class NeverCancelled:
    """Signal used when a scan is not attached to a job."""

    def request(self, job_id: int) -> None:
        return None

    def consume(self, job_id: int) -> bool:
        return False


class RedisCancellationSignal:
    """Cancel flag stored in Redis, so API and worker processes share it."""

    KEY_TTL_SECONDS = 600

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    @classmethod
    def from_url(cls, url: str) -> RedisCancellationSignal:
        return cls(Redis.from_url(url))

    @staticmethod
    def key(job_id: int) -> str:
        return f"scan_cancel:{job_id}"

    def request(self, job_id: int) -> None:
        self._redis.setex(self.key(job_id), self.KEY_TTL_SECONDS, "1")

    def consume(self, job_id: int) -> bool:
        try:
            # DELETE returns the number of removed keys: check and clear at once.
            return bool(self._redis.delete(self.key(job_id)))
        except RedisError as exc:
            # An unreachable Redis must not stop the scan.
            logger.warning("Could not read cancel flag for job #%d: %s", job_id, exc)
            return False
