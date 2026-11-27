"""
Where a client's scans run: on the platform, or on the client's probe.

Internal network scans always run on the client's probe: from the
platform they would reach the platform's own network, not the client's
(``app.scan_jobs.network_scope`` refuses them while the client has no probe
online). A client with an active probe also runs its API scans on it by
default; Root can change that list per client (e.g. external scans from the
probe too). Only scans that reach the client's network can go to a probe;
IaC scans read an uploaded file and inventory jobs read a cloud service, so
they always run on the platform.

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
# External scans stay on the platform by default: they test the client from
# the Internet, not from inside its network.
DEFAULT_PROBE_SCAN_TYPES = (ScanType.INTERNAL, ScanType.API)
# Never run from the platform, whatever Root chose.
PROBE_ONLY_SCAN_TYPES = (ScanType.INTERNAL,)
ACTIVE_PROBE = "active"


class NotDelegableError(ValueError):
    pass


def has_active_probe(db: Session, workspace_id: int) -> bool:
    """An enrolled, not revoked, probe of the client (online or not)."""
    return db.query(models.Probe.id).filter(
        models.Probe.workspace_id == workspace_id, models.Probe.status == ACTIVE_PROBE,
    ).first() is not None


def _stored_scan_types(db: Session, workspace_id: int) -> list[str] | None:
    stored = get_workspace_setting(db, workspace_id, PROBE_EXECUTION_KEY, {}).get("scan_types")
    if not isinstance(stored, list):
        return None
    delegable = {t.value for t in DELEGABLE_SCAN_TYPES}
    return [t for t in stored if t in delegable]


def probe_execution_is_default(db: Session, workspace_id: int) -> bool:
    """True while Root has not chosen the client's list explicitly."""
    return _stored_scan_types(db, workspace_id) is None


def probe_scan_types(db: Session, workspace_id: int) -> list[str]:
    stored = _stored_scan_types(db, workspace_id)
    if stored is None:
        stored = [t.value for t in DEFAULT_PROBE_SCAN_TYPES] if has_active_probe(db, workspace_id) else []
    return _with_probe_only(stored)


def _with_probe_only(scan_types: list[str]) -> list[str]:
    chosen = set(scan_types) | {t.value for t in PROBE_ONLY_SCAN_TYPES}
    return [t.value for t in DELEGABLE_SCAN_TYPES if t.value in chosen]


def set_probe_scan_types(db: Session, workspace_id: int, scan_types: list[str]) -> list[str]:
    """Raises :class:`NotDelegableError` for a type a probe cannot run."""
    delegable = [t.value for t in DELEGABLE_SCAN_TYPES]
    refused = sorted(set(scan_types) - set(delegable))
    if refused:
        raise NotDelegableError(f"Scan types that cannot run on a probe: {', '.join(refused)}")
    chosen = _with_probe_only(scan_types)
    set_workspace_setting(db, workspace_id, PROBE_EXECUTION_KEY, {"scan_types": chosen})
    return chosen


def placement_of(db: Session, workspace_id: int, scan_type: str | None) -> str:
    try:
        parsed = ScanType.parse(scan_type)
    except ValueError:
        return PLATFORM
    return PROBE if parsed.value in probe_scan_types(db, workspace_id) else PLATFORM
