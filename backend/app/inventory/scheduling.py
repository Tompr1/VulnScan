"""
When inventory connections are synced automatically (daily / weekly).
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import StrEnum

from sqlalchemy.orm import Session

from app.db import models

logger = logging.getLogger(__name__)


class SyncFrequency(StrEnum):
    MANUAL = "manual"
    DAILY = "daily"
    WEEKLY = "weekly"


_INTERVALS = {SyncFrequency.DAILY: timedelta(days=1), SyncFrequency.WEEKLY: timedelta(days=7)}


def is_due(frequency: str, last_attempt_at: datetime | None, now: datetime) -> bool:
    """Due when never attempted, or when the interval since the last attempt
    (queued or finished) has elapsed. Manual connections are never due."""
    try:
        interval = _INTERVALS.get(SyncFrequency(frequency))
    except ValueError:
        return False
    if interval is None:
        return False
    return last_attempt_at is None or now - last_attempt_at >= interval


def queue_due_syncs(
    session_factory: Callable[[], Session],
    queue_sync: Callable[[Session, models.InventoryConnection], None],
    now: datetime,
) -> int:
    """Queue a sync for every enabled connection that is due; returns how many."""
    queued = 0
    with session_factory() as db:
        for connection in db.query(models.InventoryConnection).filter(models.InventoryConnection.enabled.is_(True)):
            last_attempt = _latest(connection.last_sync_requested_at, connection.last_sync_at)
            if not is_due(connection.sync_frequency, last_attempt, now):
                continue
            try:
                queue_sync(db, connection)
                queued += 1
            except Exception as exc:  # one failing connection must not block the others
                logger.warning("Could not queue inventory sync for connection #%d: %s", connection.id, exc)
    return queued


def _latest(*moments: datetime | None) -> datetime | None:
    present = [m if m.tzinfo else m.replace(tzinfo=timezone.utc) for m in moments if m is not None]
    return max(present, default=None)
