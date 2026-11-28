"""
The reference datasets (NVD, CISA KEV, EPSS, CMS map, advisories…) are shared
by every client of the platform: one set of files, managed by a global admin,
read by every scan, audit and Threat Intel page.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.db import models

# Redis keys of the dataset refresh (one at a time for the whole platform).
REFRESH_LOCK_KEY = "dataset_refresh_lock"
REFRESH_STATUS_KEY = "dataset_refresh_status"
# RQ statuses of a job that may still run.
_LIVE_JOB_STATUSES = {"queued", "started", "deferred", "scheduled"}


def enabled_dataset_paths(db: Session, kind: str) -> list[str]:
    """Files of the enabled datasets of ``kind``, newest first."""
    rows = (
        db.query(models.CveDataset.path)
        .filter(models.CveDataset.kind == kind, models.CveDataset.enabled.is_(True))
        .order_by(models.CveDataset.id.desc())
    )
    return [row.path for row in rows]


def latest_dataset_path(db: Session, kind: str) -> str | None:
    """File of the newest enabled dataset of ``kind``, if any."""
    paths = enabled_dataset_paths(db, kind)
    return paths[0] if paths else None


def clear_abandoned_refresh(redis: Any, job_status: Callable[[str], str | None], now: datetime | None = None) -> bool:
    """Release the lock of a refresh whose job no longer runs.

    The lock holds the refresh's RQ job id. A worker killed mid-refresh (a
    deploy restarts it) never releases it: the page showed the refresh as
    running, and refused a new one, until the lock expired, up to an hour
    later. ``job_status`` gives the RQ status of a job id, None if unknown."""
    holder = redis.get(REFRESH_LOCK_KEY)
    if holder is None:
        return False
    job_id = holder.decode() if isinstance(holder, bytes) else str(holder)
    if job_status(job_id) in _LIVE_JOB_STATUSES:
        return False
    redis.delete(REFRESH_LOCK_KEY)
    raw = redis.get(REFRESH_STATUS_KEY)
    try:
        state = json.loads(raw) if raw else None
    except ValueError:
        state = None
    if isinstance(state, dict) and state.get("status") == "running":
        kinds = state.get("kinds") or {}
        for kind in kinds.values():
            if kind.get("status") == "running":
                kind.update(status="failed", message="Interrupted: the worker stopped during the refresh")
        done = any(kind.get("status") == "done" for kind in kinds.values())
        state.update(
            status="partial" if done else "failed",
            current_kind=None,
            finished_at=(now or datetime.now(timezone.utc)).isoformat(),
        )
        redis.setex(REFRESH_STATUS_KEY, 3600, json.dumps(state))
    return True
