"""
Per-workspace settings stored as JSON documents.

Lives outside the API layer so the worker and the scheduler can read
settings without importing route modules.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models

logger = logging.getLogger(__name__)

NOTIFICATION_PREFERENCES_KEY = "notification_preferences"
INVENTORY_ALERTS_KEY = "inventory_alerts"
AUTO_AI_ANALYSIS_KEY = "auto_ai_analysis"

DEFAULT_NOTIFICATION_PREFS: dict[str, dict[str, bool]] = {
    "critical_finding":     {"email": True,  "slack": True,  "webhook": True},
    "cisa_kev_match":       {"email": True,  "slack": True,  "webhook": False},
    "scan_completed":       {"email": False, "slack": True,  "webhook": False},
    "scan_failed":          {"email": True,  "slack": True,  "webhook": True},
    "new_asset_discovered": {"email": False, "slack": False, "webhook": True},
    "weekly_digest":        {"email": True,  "slack": False, "webhook": False},
    # Device inventory audits (new detections only, see app/inventory/alerts.py)
    "device_vulnerability":  {"email": True,  "slack": True,  "webhook": True},
    "device_os_issue":       {"email": True,  "slack": True,  "webhook": True},
    "device_software_issue": {"email": False, "slack": True,  "webhook": True},
}


def get_workspace_setting(db: Session, workspace_id: int, key: str, default: dict[str, Any]) -> dict[str, Any]:
    """Stored value of ``key``, or ``default`` when absent or unreadable."""
    row = _find(db, workspace_id, key)
    if row is None:
        return default
    try:
        value = json.loads(row.value_json)
    except json.JSONDecodeError:
        logger.warning("Workspace %d setting %r is not valid JSON — using default", workspace_id, key)
        return default
    return value if isinstance(value, dict) else default


def notification_preferences(db: Session, workspace_id: int) -> dict[str, dict[str, bool]]:
    """Stored preferences over the defaults: an event added after the
    workspace saved its preferences starts with its default channels."""
    stored = get_workspace_setting(db, workspace_id, NOTIFICATION_PREFERENCES_KEY, {})
    return {**DEFAULT_NOTIFICATION_PREFS, **{k: v for k, v in stored.items() if isinstance(v, dict)}}


def set_workspace_setting(db: Session, workspace_id: int, key: str, value: dict[str, Any]) -> None:
    row = _find(db, workspace_id, key)
    if row is None:
        db.add(models.WorkspaceSetting(workspace_id=workspace_id, key=key, value_json=json.dumps(value)))
    else:
        row.value_json = json.dumps(value)
        row.updated_at = datetime.now(timezone.utc)
    db.commit()


def _find(db: Session, workspace_id: int, key: str) -> models.WorkspaceSetting | None:
    return (
        db.query(models.WorkspaceSetting)
        .filter(models.WorkspaceSetting.workspace_id == workspace_id, models.WorkspaceSetting.key == key)
        .first()
    )
