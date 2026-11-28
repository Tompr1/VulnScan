"""
Which Threat Intel CVEs are on a client's fleet, and where.

A CVE is on the fleet when a current finding of the client names it
(finding_cves, filled when findings are saved). Current means: from the
latest completed job of each scan (same target, type and profile) — an older
scan of a target that was patched since does not count — and neither
suppressed nor on a device removed from the fleet manager.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.db import models

F, J, L = models.Finding, models.ScanJob, models.FindingCve
D, A = models.InventoryDevice, models.Asset

# Jobs whose findings are saved (an "analyzing" job runs its AI analysis).
_FINDINGS_SAVED = ("done", "analyzing")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
MAX_PLACES = 200


def _latest_jobs(workspace_id: int) -> Select:
    """Latest completed job of each scan of the client."""
    return (
        select(func.max(J.id))
        .where(J.workspace_id == workspace_id, J.status.in_(_FINDINGS_SAVED))
        .group_by(J.target, J.scan_type, J.profile_id)
    )


def _current_links(workspace_id: int, *columns) -> Select:
    suppressed = select(models.SuppressedFinding.fingerprint).where(
        models.SuppressedFinding.workspace_id == workspace_id
    )
    return (
        select(*columns)
        .select_from(L)
        .join(F, F.id == L.finding_id)
        .outerjoin(D, D.id == F.device_id)
        .where(
            L.workspace_id == workspace_id,
            F.workspace_id == workspace_id,
            F.job_id.in_(_latest_jobs(workspace_id)),
            F.fingerprint.not_in(suppressed),
            D.removed_at.is_(None),
        )
    )


def fleet_cves(workspace_id: int) -> Select:
    """The CVE ids on the client's fleet (a subquery for the Threat Intel list)."""
    return _current_links(workspace_id, L.cve).distinct()


def _place_key(device_id: int | None, target: str) -> tuple:
    return ("device", device_id) if device_id is not None else ("target", target)


def affected_counts(db: Session, workspace_id: int, cves: Collection[str]) -> dict[str, int]:
    """{CVE: number of places (devices, scan targets) of the fleet it is on}."""
    if not cves:
        return {}
    rows = db.execute(_current_links(workspace_id, L.cve, F.device_id, F.target).where(L.cve.in_(list(cves))))
    places: dict[str, set] = defaultdict(set)
    for cve, device_id, target in rows:
        places[cve].add(_place_key(device_id, target))
    return {cve: len(keys) for cve, keys in places.items()}


def affected_places(db: Session, workspace_id: int, cve: str) -> dict[str, Any]:
    """Where a CVE is on the client's fleet: one entry per device or scan
    target, with the findings naming it, most urgent first."""
    cve = (cve or "").strip().upper()
    rows = db.execute(
        _current_links(
            workspace_id,
            F.id, F.title, F.severity, F.risk_score, F.target, F.device_id, F.job_id,
            J.scan_type, J.finished_at, J.asset_id, A.name.label("asset_name"),
            D.name.label("device_name"), D.platform,
        )
        .join(J, J.id == F.job_id)
        .outerjoin(A, A.id == J.asset_id)
        .where(L.cve == cve)
    ).all()

    places: dict[tuple, dict[str, Any]] = {}
    for r in rows:
        key = _place_key(r.device_id, r.target)
        place = places.get(key)
        if place is None:
            place = places[key] = {
                "kind": key[0],
                "device_id": r.device_id,
                "device_name": r.device_name,
                "platform": r.platform,
                "target": r.target,
                "asset_id": r.asset_id,
                "asset_name": r.asset_name,
                "scan_type": r.scan_type,
                "job_id": r.job_id,
                "seen_at": r.finished_at.isoformat() if r.finished_at else None,
                "severity": r.severity,
                "risk_score": r.risk_score,
                "findings": [],
            }
        place["findings"].append({
            "id": r.id, "title": r.title, "severity": r.severity, "risk_score": r.risk_score, "job_id": r.job_id,
        })
        if _urgency(r.severity, r.risk_score) > _urgency(place["severity"], place["risk_score"]):
            place["severity"], place["risk_score"] = r.severity, r.risk_score

    # Most urgent first, then by name (stable sort).
    ordered = sorted(places.values(), key=lambda p: (p["device_name"] or p["asset_name"] or p["target"] or "").lower())
    ordered.sort(key=lambda p: _urgency(p["severity"], p["risk_score"]), reverse=True)
    for place in ordered:
        place["findings"].sort(key=lambda f: _urgency(f["severity"], f["risk_score"]), reverse=True)
    return {
        "cve": cve,
        "total": len(ordered),
        "truncated": len(ordered) > MAX_PLACES,
        "places": ordered[:MAX_PLACES],
    }


def _urgency(severity: str | None, risk_score: float | None) -> tuple[int, float]:
    return _SEVERITY_RANK.get((severity or "").lower(), 0), risk_score or 0.0
