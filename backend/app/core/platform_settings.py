"""
Platform-wide settings, shared by every client (JSON documents keyed by name).

What concerns a single client lives in app.core.workspace_settings.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models

logger = logging.getLogger(__name__)

DATASET_REFRESH_KEY = "dataset_refresh"
DEFAULT_DATASET_REFRESH: dict[str, Any] = {"enabled": False, "interval_hours": 24}
# When the scheduler last queued a refresh. Kept apart from the schedule so
# that saving the schedule never resets it.
DATASET_REFRESH_LAST_KEY = "dataset_refresh_last_queued"


def get_platform_setting(db: Session, key: str, default: dict[str, Any]) -> dict[str, Any]:
    """Stored value of ``key``, or a copy of ``default`` when absent or unreadable."""
    row = db.query(models.PlatformSetting).filter(models.PlatformSetting.key == key).first()
    if row is None:
        return dict(default)
    try:
        return {**default, **json.loads(row.value_json)}
    except (TypeError, ValueError):
        logger.warning("Platform setting %r is not valid JSON — using default", key)
        return dict(default)


def set_platform_setting(db: Session, key: str, value: dict[str, Any]) -> None:
    row = db.query(models.PlatformSetting).filter(models.PlatformSetting.key == key).first()
    if row is None:
        db.add(models.PlatformSetting(key=key, value_json=json.dumps(value)))
    else:
        row.value_json = json.dumps(value)
        row.updated_at = datetime.now(timezone.utc)
    db.commit()


def dataset_refresh_due(db: Session, now: datetime) -> bool:
    """Whether the scheduled dataset refresh should be queued at ``now``.

    Measured from the last time it was queued, stored in the database, so an
    API restart (every deploy) does not push the next refresh back a full
    interval. Never queued before: due at once.
    """
    cfg = get_platform_setting(db, DATASET_REFRESH_KEY, DEFAULT_DATASET_REFRESH)
    if not cfg.get("enabled"):
        return False
    try:
        interval = timedelta(hours=max(1, int(cfg.get("interval_hours", 24))))
    except (TypeError, ValueError):
        interval = timedelta(hours=24)
    last = get_platform_setting(db, DATASET_REFRESH_LAST_KEY, {}).get("at")
    try:
        last_at = datetime.fromisoformat(last)
    except (TypeError, ValueError):
        return True
    if last_at.tzinfo is None:
        last_at = last_at.replace(tzinfo=timezone.utc)
    return now - last_at >= interval


def mark_dataset_refresh_queued(db: Session, now: datetime) -> None:
    set_platform_setting(db, DATASET_REFRESH_LAST_KEY, {"at": now.isoformat()})
