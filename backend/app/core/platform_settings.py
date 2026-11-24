"""
Platform-wide settings, shared by every client (JSON documents keyed by name).

What concerns a single client lives in app.core.workspace_settings.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models

logger = logging.getLogger(__name__)

DATASET_REFRESH_KEY = "dataset_refresh"
DEFAULT_DATASET_REFRESH: dict[str, Any] = {"enabled": False, "interval_hours": 24}


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
