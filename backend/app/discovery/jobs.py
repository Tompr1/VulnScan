"""
Discovery jobs, platform side: a user starts one, the client's probe runs it.

Discovery only ever runs on the client's probe, from inside its network: the
platform never probes a network itself (it would map the MSP's own LAN). A
client without an active probe cannot discover hosts, and a range must lie
inside the client's allowlist.

    start_discovery   user        -> queued
    claim             probe       -> running (bound to that probe)
    save_progress     probe       -> addresses probed, hosts so far; answer: stop?
    finish            probe       -> done | cancelled | failed, final hosts
    request_cancel    user        -> queued: cancelled at once; running: the probe is told to stop

A client runs one discovery at a time.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.host_discovery import address_count, parse_private_network
from app.db import models
from app.discovery.assignment import DiscoveryReport, parse_hosts, parse_probed
from app.probes.placement import has_active_probe
from app.scanner.allowlist import AllowlistPolicy

logger = logging.getLogger(__name__)

QUEUED, RUNNING, DONE, CANCELLED, FAILED = "queued", "running", "done", "cancelled", "failed"
ACTIVE = (QUEUED, RUNNING)


class DiscoveryAlreadyRunningError(RuntimeError):
    def __init__(self, job: models.DiscoveryJob) -> None:
        super().__init__(f"A discovery of {job.network_range} is already running")
        self.job = job


class NoProbeError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "This client has no scan probe. Host discovery runs only from a probe installed on the "
            "client's network: ask a platform admin to install one (Root > Probes)."
        )


class RangeNotAllowedError(ValueError):
    def __init__(self, network: str, allowlist: AllowlistPolicy) -> None:
        super().__init__(f"{network} is outside this client's allowlist ({allowlist})")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── User side ───────────────────────────────────────────────────────────────

def active_discovery(db: Session, workspace_id: int) -> models.DiscoveryJob | None:
    return (
        db.query(models.DiscoveryJob)
        .filter(models.DiscoveryJob.workspace_id == workspace_id, models.DiscoveryJob.status.in_(ACTIVE))
        .order_by(models.DiscoveryJob.id.desc())
        .first()
    )


def start_discovery(
    db: Session, workspace_id: int, network_range: str, allowlist: AllowlistPolicy,
) -> models.DiscoveryJob:
    """Queue a discovery for the client's probe.

    Raises ValueError (:class:`NotPrivateNetworkError` included) for a bad
    range, :class:`RangeNotAllowedError` outside the client's allowlist,
    :class:`NoProbeError` without an active probe, and
    :class:`DiscoveryAlreadyRunningError` while another one is open."""
    net = parse_private_network(network_range)
    if not has_active_probe(db, workspace_id):
        raise NoProbeError()
    if not allowlist.allows_network(net):
        raise RangeNotAllowedError(str(net), allowlist)
    running = active_discovery(db, workspace_id)
    if running is not None:
        raise DiscoveryAlreadyRunningError(running)

    job = models.DiscoveryJob(
        workspace_id=workspace_id,
        network_range=str(net),
        status=QUEUED,
        total=address_count(net),
        probed=0,
        hosts_json="[]",
        cancel_requested=False,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    logger.info("Discovery #%d of %s queued for the probe of client #%d", job.id, job.network_range, workspace_id)
    return job


def close_stale_discoveries(db: Session, now: datetime, running_after: timedelta, unclaimed_after: timedelta) -> int:
    """Fails the discoveries no probe will finish: running for longer than
    the budget allows (the probe is gone), or never claimed (the probe is
    offline, or too old to run discoveries). Returns how many were closed."""
    stale = (
        db.query(models.DiscoveryJob)
        .filter(models.DiscoveryJob.status.in_(ACTIVE))
        .all()
    )
    closed = 0
    for job in stale:
        if job.status == RUNNING and job.started_at and _utc(job.started_at) < now - running_after:
            job.error = "The probe stopped reporting on this discovery. The hosts found so far are kept."
        elif job.status == QUEUED and _utc(job.created_at) < now - unclaimed_after:
            job.error = (
                "No probe of this client took the discovery. Check in Root > Probes that the probe is "
                "online and up to date (older probes do not run discoveries)."
            )
        else:
            continue
        job.status, job.finished_at = FAILED, now
        closed += 1
        logger.info("Stale discovery #%d (%s) marked failed", job.id, job.network_range)
    db.commit()
    return closed


def _utc(moment: datetime) -> datetime:
    # SQLite gives naive datetimes back.
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def request_cancel(db: Session, job: models.DiscoveryJob) -> None:
    """A queued job ends at once; a running one stops after the probe's
    current wave of probes."""
    if job.status == QUEUED:
        job.status, job.finished_at = CANCELLED, _now()
    elif job.status == RUNNING:
        job.cancel_requested = True
    db.commit()


def serialize(job: models.DiscoveryJob, known: dict[str, tuple[int, str]]) -> dict[str, Any]:
    """The job as the page shows it; each host carries the asset it is
    already on, read now, so a host added since the run shows as known."""
    hosts = []
    for host in json.loads(job.hosts_json or "[]"):
        asset = known.get(host["ip"])
        hosts.append({
            "ip": host["ip"],
            "hostname": host.get("hostname"),
            "asset_id": asset[0] if asset else None,
            "asset_name": asset[1] if asset else None,
        })
    return {
        "id": job.id,
        "type": "network",
        "network_range": job.network_range,
        "status": job.status,
        "total": job.total,
        "probed": job.probed,
        "cancel_requested": bool(job.cancel_requested),
        "error": job.error,
        "probe_id": job.probe_id,
        "hosts": hosts,
        "count": len(hosts),
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


# ── Probe side (through app.probes.gateway) ─────────────────────────────────

def claim(db: Session, workspace_id: int, probe_id: int, clock: Callable[[], datetime]) -> models.DiscoveryJob | None:
    """The client's oldest queued discovery, now running on this probe."""
    candidates = [
        discovery_id for (discovery_id,) in db.query(models.DiscoveryJob.id)
        .filter(models.DiscoveryJob.workspace_id == workspace_id, models.DiscoveryJob.status == QUEUED)
        .order_by(models.DiscoveryJob.id)
        .limit(5)
    ]
    for discovery_id in candidates:
        # Conditional: of two probes asking at once, one gets it.
        claimed = (
            db.query(models.DiscoveryJob)
            .filter(models.DiscoveryJob.id == discovery_id, models.DiscoveryJob.status == QUEUED)
            .update({"status": RUNNING, "started_at": clock(), "probe_id": probe_id})
        )
        db.commit()
        if claimed == 1:
            return db.get(models.DiscoveryJob, discovery_id)
    return None


def own_running(db: Session, workspace_id: int, probe_id: int, discovery_id: int) -> models.DiscoveryJob | None:
    """The discovery if it is running on this probe of this client."""
    return db.query(models.DiscoveryJob).filter(
        models.DiscoveryJob.id == discovery_id,
        models.DiscoveryJob.workspace_id == workspace_id,
        models.DiscoveryJob.probe_id == probe_id,
        models.DiscoveryJob.status == RUNNING,
    ).first()


def save_progress(db: Session, job: models.DiscoveryJob, document: Any) -> bool:
    """Stores what the probe found so far; True when it must stop.
    Raises ValueError for an unreadable document."""
    if not isinstance(document, dict):
        raise ValueError("Expected {\"probed\": n, \"hosts\": [...]}")
    net = parse_private_network(job.network_range)
    job.probed = parse_probed(document.get("probed"), job.total)
    job.hosts_json = json.dumps(parse_hosts(document.get("hosts", []), net))
    db.commit()
    return bool(job.cancel_requested)


def finish(db: Session, job: models.DiscoveryJob, data: Any) -> DiscoveryReport:
    """Closes the discovery with the probe's report. Raises ValueError."""
    if not isinstance(data, dict):
        raise ValueError("Expected a discovery report")
    try:
        report = DiscoveryReport.from_dict(data)
    except (KeyError, TypeError) as exc:
        raise ValueError(f"Unreadable report: {exc}") from exc
    if report.discovery_id != job.id:
        raise ValueError("The report names another discovery")
    hosts = parse_hosts(report.hosts, parse_private_network(job.network_range))
    job.status = report.status
    job.probed = job.total if report.status == DONE else parse_probed(report.probed, job.total)
    job.hosts_json = json.dumps(hosts)
    job.error = report.error
    job.finished_at = _now()
    db.commit()
    logger.info("Discovery #%d %s on probe #%s: %d host(s)", job.id, job.status, job.probe_id, len(hosts))
    return report
