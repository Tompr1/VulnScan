"""Which scan targets of a client already belong to one of its assets."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.db import models


def known_targets(db: Session, workspace_id: int) -> dict[str, tuple[int, str]]:
    """Target → (asset id, asset name) for every target already on an asset:
    registered ones, and those a scan job ran against under an asset."""
    known: dict[str, tuple[int, str]] = {}
    registered = (
        db.query(models.AssetTarget.target, models.Asset.id, models.Asset.name)
        .join(models.Asset, models.Asset.id == models.AssetTarget.asset_id)
        .filter(models.AssetTarget.workspace_id == workspace_id)
        .all()
    )
    scanned = (
        db.query(models.ScanJob.target, models.Asset.id, models.Asset.name)
        .join(models.Asset, models.Asset.id == models.ScanJob.asset_id)
        .filter(models.ScanJob.workspace_id == workspace_id)
        .all()
    )
    for target, asset_id, asset_name in [*registered, *scanned]:
        known.setdefault(target, (asset_id, asset_name))
    return known
