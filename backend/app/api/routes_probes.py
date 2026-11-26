"""
Administration of the scan probes by a global admin (Root): create a probe
for a client and hand its enrollment token to whoever installs the VM,
renew or revoke it, and choose which of a client's scans run on its probe.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_global_admin
from app.core.config import settings
from app.db import models
from app.probes.placement import DELEGABLE_SCAN_TYPES, PROBE, NotDelegableError, probe_scan_types, set_probe_scan_types
from app.probes.registry import Enrollment, ProbeRegistry, ProbeStateError, display_status
from app.scan_jobs.outcome import JobStatus

router = APIRouter(prefix="/probes", tags=["probes"], dependencies=[Depends(require_global_admin)])


class ProbeCreateBody(BaseModel):
    workspace_id: int
    name: str = Field(min_length=1, max_length=255)


class ExecutionBody(BaseModel):
    scan_types: list[str]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _registry(db: Session) -> ProbeRegistry:
    return ProbeRegistry(db, timedelta(hours=settings.PROBE_ENROLLMENT_TTL_HOURS))


@router.get("")
def list_probes(db: Session = Depends(get_db)):
    now = _now()
    clients = db.query(models.Workspace).order_by(models.Workspace.name).all()
    names = {client.id: client.name for client in clients}
    running = dict(
        db.query(models.ScanJob.probe_id, func.count(models.ScanJob.id))
        .filter(models.ScanJob.status == JobStatus.RUNNING.value, models.ScanJob.probe_id.isnot(None))
        .group_by(models.ScanJob.probe_id)
    )
    waiting = dict(
        db.query(models.ScanJob.workspace_id, func.count(models.ScanJob.id))
        .filter(models.ScanJob.status == JobStatus.QUEUED.value, models.ScanJob.runs_on == PROBE)
        .group_by(models.ScanJob.workspace_id)
    )
    probes = db.query(models.Probe).order_by(models.Probe.workspace_id, models.Probe.name).all()
    return {
        "probes": [_probe(p, names, now, running.get(p.id, 0)) for p in probes],
        "clients": [
            {
                "id": client.id,
                "name": client.name,
                "probe_scan_types": probe_scan_types(db, client.id),
                "waiting_jobs": waiting.get(client.id, 0),
            }
            for client in clients
        ],
        "delegable_scan_types": [t.value for t in DELEGABLE_SCAN_TYPES],
        "desired_image": settings.PROBE_IMAGE.strip() or None,
    }


@router.post("", status_code=201)
def create_probe(body: ProbeCreateBody, db: Session = Depends(get_db)):
    client = db.get(models.Workspace, body.workspace_id)
    if client is None:
        raise HTTPException(404, "Client not found")
    enrollment = _registry(db).create(client.id, body.name.strip(), _now())
    probe = db.get(models.Probe, enrollment.probe_id)
    return {**_probe(probe, {client.id: client.name}, _now(), 0), "enrollment": _enrollment(enrollment)}


@router.post("/{probe_id}/enrollment")
def renew_enrollment(probe_id: int, db: Session = Depends(get_db)):
    """A new one-time token, e.g. for a reinstalled VM: once used, the
    probe's previous secret no longer works."""
    probe = _get(db, probe_id)
    try:
        return _enrollment(_registry(db).new_enrollment(probe, _now()))
    except ProbeStateError as exc:
        raise HTTPException(409, str(exc)) from None


@router.post("/{probe_id}/revoke")
def revoke_probe(probe_id: int, db: Session = Depends(get_db)):
    probe = _get(db, probe_id)
    _registry(db).revoke(probe)
    client = db.get(models.Workspace, probe.workspace_id)
    return _probe(probe, {probe.workspace_id: client.name if client else ""}, _now(), 0)


@router.delete("/{probe_id}")
def delete_probe(probe_id: int, db: Session = Depends(get_db)):
    probe = _get(db, probe_id)
    db.query(models.ScanJob).filter(models.ScanJob.probe_id == probe.id).update({"probe_id": None})
    db.delete(probe)
    db.commit()
    return {"deleted": probe_id}


@router.put("/clients/{workspace_id}/execution")
def set_client_execution(workspace_id: int, body: ExecutionBody, db: Session = Depends(get_db)):
    """The scan types of this client that run on its probe; the others run
    on the platform. Applies to jobs queued from now on."""
    if db.get(models.Workspace, workspace_id) is None:
        raise HTTPException(404, "Client not found")
    try:
        chosen = set_probe_scan_types(db, workspace_id, body.scan_types)
    except NotDelegableError as exc:
        raise HTTPException(422, str(exc)) from None
    return {"workspace_id": workspace_id, "probe_scan_types": chosen}


def _get(db: Session, probe_id: int) -> models.Probe:
    probe = db.get(models.Probe, probe_id)
    if probe is None:
        raise HTTPException(404, "Probe not found")
    return probe


def _probe(probe: models.Probe, client_names: dict[int, str], now: datetime, running_jobs: int) -> dict:
    return {
        "id": probe.id,
        "workspace_id": probe.workspace_id,
        "client_name": client_names.get(probe.workspace_id, ""),
        "name": probe.name,
        "status": display_status(probe, now, settings.PROBE_ONLINE_SECONDS),
        "hostname": probe.hostname,
        "version": probe.version,
        "last_seen_at": _iso(probe.last_seen_at),
        "last_seen_ip": probe.last_seen_ip,
        "enrolled_at": _iso(probe.enrolled_at),
        "enrollment_expires_at": _iso(probe.enrollment_expires_at),
        "created_at": _iso(probe.created_at),
        "running_jobs": running_jobs,
    }


def _enrollment(enrollment: Enrollment) -> dict:
    return {"token": enrollment.token, "expires_at": _iso(enrollment.expires_at)}


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat()
