"""
SQLAlchemy persistence of the inventory.

Write side (SqlInventoryRepository) for the sync, read side
(SqlInventoryReadModel) for the device pages: the API never builds domain
objects just to serialise them.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable, Collection, Sequence
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.db import models
from app.inventory.audit.service import AuditedDevice, AuditRun
from app.inventory.changes import DeviceChange
from app.inventory.domain import Device, InstalledApp, InventorySnapshot, Platform
from app.risk.severity import Severity

SessionFactory = Callable[[], Session]

_DEVICE_FIELDS = (
    "name", "os_name", "os_version", "model", "manufacturer", "serial_number", "user_principal_name",
    "ownership", "compliance_state", "is_encrypted", "security_patch_level",
)
_MAX_CHANGES_ON_DETAIL = 200
# Job statuses whose findings are stored: an audit still running, or whose
# job failed before saving, is not the device's current state.
_FINDINGS_SAVED = ("done", "analyzing")
_SEVERITY_ORDER = list(Severity)  # most severe first


class SqlInventoryRepository:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def active_devices(self, connection_id: int) -> dict[str, Device]:
        return {entry.device.external_id: entry.device for entry in self.devices_to_audit(connection_id)}

    def devices_to_audit(self, connection_id: int) -> list[AuditedDevice]:
        with self._session_factory() as db:
            rows = (
                db.query(models.InventoryDevice)
                .filter(models.InventoryDevice.connection_id == connection_id, models.InventoryDevice.removed_at.is_(None))
                .order_by(models.InventoryDevice.id)
                .all()
            )
            apps = _apps_by_device(db, [row.id for row in rows])
            return [AuditedDevice(row.id, _device_of(row, apps.get(row.id, ()))) for row in rows]

    def record_audit(self, run: AuditRun) -> None:
        with self._session_factory() as db:
            db.add(models.InventoryAuditRun(
                connection_id=run.connection_id, job_id=run.job_id, audited_at=run.audited_at,
                devices=run.devices, issues=run.issues, warnings="\n".join(run.warnings),
            ))
            db.commit()

    def save_snapshot(
        self, connection_id: int, workspace_id: int, snapshot: InventorySnapshot, changes: Sequence[DeviceChange]
    ) -> None:
        at = snapshot.collected_at
        with self._session_factory() as db:
            rows = {
                row.external_id: row
                for row in db.query(models.InventoryDevice).filter(models.InventoryDevice.connection_id == connection_id)
            }
            current_ids = set()
            for device in snapshot.devices:
                row = rows.get(device.external_id)
                if row is None:
                    row = models.InventoryDevice(
                        workspace_id=workspace_id, connection_id=connection_id,
                        external_id=device.external_id, first_seen_at=at,
                    )
                    db.add(row)
                    rows[device.external_id] = row
                _copy_device(device, row, at)
                current_ids.add(device.external_id)
            for external_id, row in rows.items():
                if external_id not in current_ids and row.removed_at is None:
                    row.removed_at = at
            db.flush()  # assigns ids to the new devices

            synced = [rows[d.external_id].id for d in snapshot.devices]
            if synced:
                db.query(models.InventoryDeviceApp).filter(models.InventoryDeviceApp.device_id.in_(synced)).delete(
                    synchronize_session=False
                )
            db.add_all(
                models.InventoryDeviceApp(device_id=rows[d.external_id].id, name=a.name[:512], version=a.version, publisher=a.publisher)
                for d in snapshot.devices
                for a in d.apps
            )
            db.add_all(
                models.InventoryDeviceChange(
                    device_id=rows[c.device_external_id].id, kind=c.kind.value, subject=c.subject[:512],
                    before=_short(c.before), after=_short(c.after), detected_at=at,
                )
                for c in changes
            )
            db.commit()


class SqlInventoryReadModel:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def list_devices(self, workspace_id: int, platform: str | None = None, search: str | None = None) -> list[dict[str, Any]]:
        with self._session_factory() as db:
            app_count = (
                db.query(models.InventoryDeviceApp.device_id, func.count(models.InventoryDeviceApp.id).label("n"))
                .group_by(models.InventoryDeviceApp.device_id)
                .subquery()
            )
            query = (
                db.query(models.InventoryDevice, app_count.c.n)
                .outerjoin(app_count, app_count.c.device_id == models.InventoryDevice.id)
                .filter(models.InventoryDevice.workspace_id == workspace_id, models.InventoryDevice.removed_at.is_(None))
            )
            if platform:
                query = query.filter(models.InventoryDevice.platform == platform)
            if search:
                pattern = f"%{search.lower()}%"
                query = query.filter(or_(
                    func.lower(models.InventoryDevice.name).like(pattern),
                    func.lower(models.InventoryDevice.user_principal_name).like(pattern),
                    func.lower(models.InventoryDevice.serial_number).like(pattern),
                ))
            rows = query.order_by(models.InventoryDevice.name).all()
            issues = _issue_summaries(db, _latest_audit_jobs(db, {row.connection_id for row, _ in rows}).values())
            return [
                {**_device_summary(row), "app_count": count or 0, **issues.get(row.id, _NO_ISSUES)}
                for row, count in rows
            ]

    def device_detail(self, workspace_id: int, device_id: int) -> dict[str, Any] | None:
        with self._session_factory() as db:
            row = (
                db.query(models.InventoryDevice)
                .filter(models.InventoryDevice.workspace_id == workspace_id, models.InventoryDevice.id == device_id)
                .first()
            )
            if row is None:
                return None
            apps = (
                db.query(models.InventoryDeviceApp)
                .filter(models.InventoryDeviceApp.device_id == row.id)
                .order_by(func.lower(models.InventoryDeviceApp.name))
            )
            changes = (
                db.query(models.InventoryDeviceChange)
                .filter(models.InventoryDeviceChange.device_id == row.id)
                .order_by(models.InventoryDeviceChange.detected_at.desc(), models.InventoryDeviceChange.id.desc())
                .limit(_MAX_CHANGES_ON_DETAIL)
            )
            audit = _latest_audit(db, row.connection_id)
            return {
                **_device_summary(row),
                "first_seen_at": _iso(row.first_seen_at),
                "removed_at": _iso(row.removed_at),
                "last_audit": _audit_summary(audit),
                "issues": _device_issues(db, row.id, audit.job_id) if audit else [],
                "apps": [{"name": a.name, "version": a.version, "publisher": a.publisher} for a in apps],
                "changes": [
                    {"kind": c.kind, "subject": c.subject, "before": c.before, "after": c.after, "detected_at": _iso(c.detected_at)}
                    for c in changes
                ],
            }


_NO_ISSUES = {"issue_count": 0, "highest_severity": None}


def _completed_audits(db: Session):
    return (
        db.query(models.InventoryAuditRun)
        .join(models.ScanJob, models.ScanJob.id == models.InventoryAuditRun.job_id)
        .filter(models.ScanJob.status.in_(_FINDINGS_SAVED))
    )


def _latest_audit(db: Session, connection_id: int) -> models.InventoryAuditRun | None:
    return (
        _completed_audits(db)
        .filter(models.InventoryAuditRun.connection_id == connection_id)
        .order_by(models.InventoryAuditRun.id.desc())
        .first()
    )


def _latest_audit_jobs(db: Session, connection_ids: Collection[int]) -> dict[int, int]:
    """{connection id: job id of its latest completed audit}."""
    if not connection_ids:
        return {}
    latest = (
        _completed_audits(db)
        .filter(models.InventoryAuditRun.connection_id.in_(connection_ids))
        .with_entities(models.InventoryAuditRun.connection_id, func.max(models.InventoryAuditRun.id).label("audit_id"))
        .group_by(models.InventoryAuditRun.connection_id)
        .subquery()
    )
    rows = db.query(models.InventoryAuditRun.connection_id, models.InventoryAuditRun.job_id).join(
        latest, latest.c.audit_id == models.InventoryAuditRun.id
    )
    return dict(rows.all())


def _issue_summaries(db: Session, job_ids: Collection[int]) -> dict[int, dict[str, Any]]:
    """{device id: issue count and highest severity} in the given audit jobs."""
    counts: dict[int, list[str]] = defaultdict(list)
    if job_ids:
        rows = db.query(models.Finding.device_id, models.Finding.severity).filter(
            models.Finding.job_id.in_(list(job_ids)), models.Finding.device_id.isnot(None)
        )
        for device_id, severity in rows:
            counts[device_id].append(severity)
    return {
        device_id: {"issue_count": len(severities), "highest_severity": min(severities, key=_severity_rank)}
        for device_id, severities in counts.items()
    }


def _device_issues(db: Session, device_id: int, job_id: int) -> list[dict[str, Any]]:
    rows = (
        db.query(models.Finding)
        .filter(models.Finding.device_id == device_id, models.Finding.job_id == job_id)
        .order_by(models.Finding.risk_score.desc(), models.Finding.id)
    )
    return [
        {
            "id": f.id,
            "rule": f.plugin_id.removeprefix("inventory."),
            "title": f.title,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "confidence": f.confidence,
            "description": f.description,
            "remediation": f.remediation,
            "evidence": f.evidence,
            "references": json.loads(f.references_json or "[]"),
            "status": f.status,
            "sla_days": f.sla_days,
            "fingerprint": f.fingerprint,
            "job_id": f.job_id,
        }
        for f in rows
    ]


def _audit_summary(audit: models.InventoryAuditRun | None) -> dict[str, Any] | None:
    if audit is None:
        return None
    return {
        "job_id": audit.job_id,
        "audited_at": _iso(audit.audited_at),
        "devices": audit.devices,
        "issues": audit.issues,
        "warnings": [line for line in (audit.warnings or "").splitlines() if line],
    }


def _severity_rank(label: str) -> int:
    severity = Severity.parse(label)
    return _SEVERITY_ORDER.index(severity) if severity else len(_SEVERITY_ORDER)


def _copy_device(device: Device, row: models.InventoryDevice, at: datetime) -> None:
    for field_name in _DEVICE_FIELDS:
        setattr(row, field_name, getattr(device, field_name))
    row.platform = device.platform.value
    row.last_check_in_at = device.last_check_in_at
    row.last_seen_at = at
    row.removed_at = None


def _apps_by_device(db: Session, device_ids: list[int]) -> dict[int, list[InstalledApp]]:
    apps: dict[int, list[InstalledApp]] = defaultdict(list)
    if device_ids:
        for app in db.query(models.InventoryDeviceApp).filter(models.InventoryDeviceApp.device_id.in_(device_ids)):
            apps[app.device_id].append(InstalledApp(app.name, app.version, app.publisher))
    return apps


def _device_of(row: models.InventoryDevice, apps: Sequence[InstalledApp]) -> Device:
    return Device(
        external_id=row.external_id,
        platform=Platform(row.platform),
        last_check_in_at=_utc(row.last_check_in_at),
        apps=tuple(apps),
        **{field_name: getattr(row, field_name) for field_name in _DEVICE_FIELDS},
    )


def _device_summary(row: models.InventoryDevice) -> dict[str, Any]:
    return {
        "id": row.id,
        "connection_id": row.connection_id,
        "external_id": row.external_id,
        "name": row.name,
        "platform": row.platform,
        "os_name": row.os_name,
        "os_version": row.os_version,
        "model": row.model,
        "manufacturer": row.manufacturer,
        "serial_number": row.serial_number,
        "user_principal_name": row.user_principal_name,
        "ownership": row.ownership,
        "compliance_state": row.compliance_state,
        "is_encrypted": row.is_encrypted,
        "security_patch_level": row.security_patch_level,
        "last_check_in_at": _iso(row.last_check_in_at),
        "last_seen_at": _iso(row.last_seen_at),
    }


def _short(value: str | None) -> str | None:
    return value[:255] if value else value


def _utc(moment: datetime | None) -> datetime | None:
    """Columns are UTC; SQLite returns them without timezone, Postgres with."""
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment: datetime | None) -> str | None:
    return _utc(moment).isoformat() if moment else None
