"""
/inventory — fleet manager connections (Intune) and the device inventory.

Secrets are write-only: stored encrypted, never returned.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.api.schemas.inventory import CreateIntuneConnectionRequest, UpdateIntuneConnectionRequest
from app.core.crypto import encrypt_str
from app.core.job_queue import QueueUnavailableError, ScanJobQueue, get_job_queue
from app.db import models
from app.db.session import SessionLocal
from app.inventory.collector import SourceFactory, credentials_of, intune_source
from app.inventory.domain import Platform
from app.inventory.intune.graph_client import GraphError
from app.inventory.repository import SqlInventoryReadModel
from app.scan_jobs.submission import ScanJobSubmission

logger = logging.getLogger("vulnscan.inventory")

router = APIRouter(prefix="/inventory", tags=["inventory"])

INTUNE = "intune"


def get_inventory_source_factory() -> SourceFactory:
    return intune_source


def get_inventory_read_model() -> SqlInventoryReadModel:
    return SqlInventoryReadModel(SessionLocal)


# ─── Connections ───────────────────────────────────────────────────────────────

@router.get("/connections")
def list_connections(user=Depends(require_role("admin", "analyst", "viewer")), db: Session = Depends(get_db)):
    rows = (
        db.query(models.InventoryConnection)
        .filter(models.InventoryConnection.workspace_id == user["ws"])
        .order_by(models.InventoryConnection.name)
    )
    return [_public(row) for row in rows]


@router.post("/connections", status_code=201)
def create_connection(
    body: CreateIntuneConnectionRequest,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    row = models.InventoryConnection(
        workspace_id=user["ws"],
        provider=INTUNE,
        name=body.name,
        tenant_id=str(body.tenant_id),
        client_id=str(body.client_id),
        client_secret_enc=encrypt_str(body.client_secret.get_secret_value()),
        sync_frequency=body.sync_frequency,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    logger.info("Inventory connection #%d created (%s)", row.id, row.name)
    return _public(row)


@router.put("/connections/{connection_id}")
def update_connection(
    connection_id: int,
    body: UpdateIntuneConnectionRequest,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    row = _connection_or_404(db, user["ws"], connection_id)
    changes = body.model_dump(exclude_unset=True, exclude={"client_secret"})
    for field_name, value in changes.items():
        setattr(row, field_name, str(value) if field_name in ("tenant_id", "client_id") else value)
    if body.client_secret is not None:
        row.client_secret_enc = encrypt_str(body.client_secret.get_secret_value())
    db.commit()
    db.refresh(row)
    return _public(row)


@router.delete("/connections/{connection_id}")
def delete_connection(connection_id: int, user=Depends(require_role("admin")), db: Session = Depends(get_db)):
    row = _connection_or_404(db, user["ws"], connection_id)
    devices = db.query(models.InventoryDevice.id).filter(models.InventoryDevice.connection_id == row.id)
    # Findings stay (job history) but lose their device link.
    db.query(models.Finding).filter(models.Finding.device_id.in_(devices)).update(
        {models.Finding.device_id: None}, synchronize_session=False
    )
    db.query(models.InventoryAuditRun).filter(models.InventoryAuditRun.connection_id == row.id).delete(synchronize_session=False)
    db.query(models.InventoryDeviceChange).filter(models.InventoryDeviceChange.device_id.in_(devices)).delete(synchronize_session=False)
    db.query(models.InventoryDeviceApp).filter(models.InventoryDeviceApp.device_id.in_(devices)).delete(synchronize_session=False)
    removed = db.query(models.InventoryDevice).filter(models.InventoryDevice.connection_id == row.id).delete(synchronize_session=False)
    db.delete(row)
    db.commit()
    return {"ok": True, "deleted_devices": removed}


@router.post("/connections/{connection_id}/test")
def test_connection(
    connection_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
    source_factory: SourceFactory = Depends(get_inventory_source_factory),
):
    """Checks the credentials and the Graph permission with one cheap call."""
    row = _connection_or_404(db, user["ws"], connection_id)
    try:
        source_factory(credentials_of(row)).check_access()
    except GraphError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "message": "Connected to Microsoft Intune"}


@router.post("/connections/{connection_id}/sync", status_code=202)
def sync_connection(
    connection_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
    queue: ScanJobQueue = Depends(get_job_queue),
):
    row = _connection_or_404(db, user["ws"], connection_id)
    try:
        job = ScanJobSubmission(db, queue).submit_inventory(row, user.get("uid"), datetime.now(timezone.utc))
    except QueueUnavailableError as exc:
        raise HTTPException(503, f"Could not enqueue inventory sync: {exc}")
    return {"job_id": job.id, "status": job.status}


# ─── Devices ───────────────────────────────────────────────────────────────────

@router.get("/devices")
def list_devices(
    platform: Platform | None = Query(default=None),
    q: str | None = Query(default=None, max_length=100),
    user=Depends(require_role("admin", "analyst", "viewer")),
    read_model: SqlInventoryReadModel = Depends(get_inventory_read_model),
):
    return read_model.list_devices(user["ws"], platform.value if platform else None, (q or "").strip() or None)


@router.get("/devices/{device_id}")
def device_detail(
    device_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    read_model: SqlInventoryReadModel = Depends(get_inventory_read_model),
):
    """Everything known about one device: the target of alert deep links."""
    device = read_model.device_detail(user["ws"], device_id)
    if device is None:
        raise HTTPException(404, "device not found")
    return device


def _connection_or_404(db: Session, workspace_id: int, connection_id: int) -> models.InventoryConnection:
    row = (
        db.query(models.InventoryConnection)
        .filter(models.InventoryConnection.workspace_id == workspace_id, models.InventoryConnection.id == connection_id)
        .first()
    )
    if row is None:
        raise HTTPException(404, "inventory connection not found")
    return row


def _public(row: models.InventoryConnection) -> dict[str, Any]:
    return {
        "id": row.id,
        "provider": row.provider,
        "name": row.name,
        "tenant_id": row.tenant_id,
        "client_id": row.client_id,
        "has_client_secret": bool(row.client_secret_enc),
        "sync_frequency": row.sync_frequency,
        "enabled": row.enabled,
        "last_sync_at": row.last_sync_at.isoformat() if row.last_sync_at else None,
        "last_sync_status": row.last_sync_status,
        "last_sync_message": row.last_sync_message,
    }
