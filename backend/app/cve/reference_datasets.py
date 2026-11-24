"""
The reference datasets (NVD, CISA KEV, EPSS, CMS map, advisories…) are shared
by every client of the platform: one set of files, managed by a global admin,
read by every scan, audit and Threat Intel page.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.db import models

# Redis keys of the dataset refresh (one at a time for the whole platform).
REFRESH_LOCK_KEY = "dataset_refresh_lock"
REFRESH_STATUS_KEY = "dataset_refresh_status"


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
