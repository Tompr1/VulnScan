"""
Where a client's scans run: on the platform, or on the client's probe.

Each client lists the scan types its probe runs (none by default). Only
scans that reach the client's network can go to a probe; IaC scans read an
uploaded file and inventory jobs read a cloud service, so they always run on
the platform.

Host discovery is not a scan type: it only ever runs on the client's probe
(``app.discovery.jobs``).
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.workspace_settings import get_workspace_setting, set_workspace_setting
from app.db import models
from app.scanner.target import ScanType

PROBE_EXECUTION_KEY = "probe_execution"
PLATFORM, PROBE = "platform", "probe"
DELEGABLE_SCAN_TYPES = (ScanType.INTERNAL, ScanType.EXTERNAL, ScanType.API)
ACTIVE_PROBE = "active"


class NotDelegableError(ValueError):
    pass


def has_active_probe(db: Session, workspace_id: int) -> bool:
    """An enrolled, not revoked, probe of the client (online or not)."""
    return db.query(models.Probe.id).filter(
        models.Probe.workspace_id == workspace_id, models.Probe.status == ACTIVE_PROBE,
    ).first() is not None


def probe_scan_types(db: Session, workspace_id: int) -> list[str]:
    stored = get_workspace_setting(db, workspace_id, PROBE_EXECUTION_KEY, {}).get("scan_types")
    if not isinstance(stored, list):
        return []
    delegable = {t.value for t in DELEGABLE_SCAN_TYPES}
    return [t for t in stored if t in delegable]


def set_probe_scan_types(db: Session, workspace_id: int, scan_types: list[str]) -> list[str]:
    """Raises :class:`NotDelegableError` for a type a probe cannot run."""
    delegable = [t.value for t in DELEGABLE_SCAN_TYPES]
    refused = sorted(set(scan_types) - set(delegable))
    if refused:
        raise NotDelegableError(f"Scan types that cannot run on a probe: {', '.join(refused)}")
    chosen = [t for t in delegable if t in set(scan_types)]
    set_workspace_setting(db, workspace_id, PROBE_EXECUTION_KEY, {"scan_types": chosen})
    return chosen


def placement_of(db: Session, workspace_id: int, scan_type: str | None) -> str:
    try:
        parsed = ScanType.parse(scan_type)
    except ValueError:
        return PLATFORM
    return PROBE if parsed.value in probe_scan_types(db, workspace_id) else PLATFORM
