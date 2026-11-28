"""
Whether a client may launch an internal network scan now.

An internal scan runs on the client's probe only: from the platform it would
reach the platform's own network, not the client's. So it is refused while
the client has no probe online, and for a target outside the client's
allowed networks (the allowlist the probe also enforces).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.probes.placement import ACTIVE_PROBE, PROBE_ONLY_SCAN_TYPES
from app.scanner.client_allowlists import client_policy
from app.scanner.target import InvalidTargetError, ScanType

NO_PROBE, PROBE_OFFLINE, OUTSIDE_ALLOWLIST = "no_probe", "probe_offline", "outside_allowlist"


class NetworkScanRefused(Exception):
    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class NetworkScanAvailability:
    available: bool
    reason: str | None
    message: str | None
    allowlist: str

    def to_dict(self) -> dict:
        return {"available": self.available, "reason": self.reason, "message": self.message, "allowlist": self.allowlist}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def requires_probe(scan_type: str | None) -> bool:
    try:
        return ScanType.parse(scan_type) in PROBE_ONLY_SCAN_TYPES
    except ValueError:
        return False


def availability(db: Session, workspace_id: int, now: datetime) -> NetworkScanAvailability:
    """Whether the client has a probe online to run its internal scans."""
    allowlist = str(client_policy(db, workspace_id, settings.ALLOWLIST))
    probes = db.query(models.Probe).filter(
        models.Probe.workspace_id == workspace_id, models.Probe.status == ACTIVE_PROBE,
    ).all()
    if not probes:
        return NetworkScanAvailability(
            False, NO_PROBE,
            "This client has no scan probe: network scans run from the client's probe only.",
            allowlist,
        )
    online_after = now - timedelta(seconds=settings.PROBE_ONLINE_SECONDS)
    if not any((_utc(p.last_seen_at) or datetime.min.replace(tzinfo=timezone.utc)) >= online_after for p in probes):
        return NetworkScanAvailability(
            False, PROBE_OFFLINE,
            "This client's scan probe is offline: network scans resume when it is back online.",
            allowlist,
        )
    return NetworkScanAvailability(True, None, None, allowlist)


def check_scan(db: Session, workspace_id: int, scan_type: str | None, target: str, now: datetime) -> None:
    """Raises :class:`NetworkScanRefused` when this scan may not be launched now."""
    if not requires_probe(scan_type):
        return
    state = availability(db, workspace_id, now)
    if not state.available:
        raise NetworkScanRefused(state.reason, state.message)
    check_target(db, workspace_id, scan_type, target)


def check_target(db: Session, workspace_id: int, scan_type: str | None, target: str) -> None:
    """Raises :class:`NetworkScanRefused` for a target outside the client's
    allowed networks (internal scans only)."""
    if not requires_probe(scan_type):
        return
    policy = client_policy(db, workspace_id, settings.ALLOWLIST)
    try:
        allowed = policy.allows_target(target, ScanType.INTERNAL)
    except InvalidTargetError:
        return  # an unusable target is reported by the scan itself
    if not allowed:
        raise NetworkScanRefused(
            OUTSIDE_ALLOWLIST,
            f"'{target}' is outside this client's allowed networks ({policy}).",
        )
