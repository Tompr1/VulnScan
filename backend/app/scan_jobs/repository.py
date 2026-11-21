"""
Persistence port of the scan job use case and its SQLAlchemy adapter.

Every adapter method opens its own short session. The scan itself runs
between two calls, so no transaction is ever left "idle in transaction"
during a scan: such a transaction holds locks on ``scan_jobs`` and makes the
startup migrations (ALTER TABLE) — and then every reader — wait behind it.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from sqlalchemy.orm import Session

from app.core.workspace_settings import notification_preferences
from app.cve.dataset_loader import load_json
from app.db import models
from app.scan_jobs.notifications import Integration
from app.scan_jobs.processing import ProcessedFinding
from app.scanner.profile import ScanProfile

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

_MAX_TRACEBACK_CHARS = 2000


@dataclass(frozen=True)
class ScanJobSnapshot:
    """Plain copy of a ``scan_jobs`` row, safe to use outside a session."""

    id: int
    workspace_id: int
    target: str
    scan_type: str
    profile_id: int | None
    meta: dict[str, Any]
    created_at: datetime | None = None

    @property
    def web_auth(self) -> dict[str, Any] | None:
        web_auth = self.meta.get("web_auth")
        return web_auth if isinstance(web_auth, dict) else None

    @property
    def ephemeral_credential_id(self) -> int | None:
        """Credential to delete once the scan is over ("auto-delete after scan")."""
        if not self.meta.get("web_auth_credential_ephemeral") or not self.web_auth:
            return None
        try:
            return int(self.web_auth["credential_id"])
        except (KeyError, TypeError, ValueError):
            return None

    def scanner_config(self, key: str) -> dict[str, Any]:
        config = self.meta.get(key)
        return config if isinstance(config, dict) else {}


@dataclass(frozen=True)
class JobFailure:
    error: str
    error_type: str
    detail: str | None = None
    traceback: str | None = None

    def to_meta(self) -> dict[str, Any]:
        meta: dict[str, Any] = {"error": self.error[:500], "error_type": self.error_type}
        if self.detail:
            meta["error_detail"] = self.detail
        if self.traceback:
            meta["traceback"] = self.traceback[:_MAX_TRACEBACK_CHARS]
        return meta


@dataclass(frozen=True)
class JobCompletion:
    findings_total: int
    findings_saved: int
    findings_dropped: int
    min_confidence_threshold: float

    def to_meta(self) -> dict[str, Any]:
        return {
            "findings_total": self.findings_total,
            "findings_saved": self.findings_saved,
            "findings_dropped": self.findings_dropped,
            "min_confidence_threshold": self.min_confidence_threshold,
        }


class ScanJobRepository(Protocol):
    def load_job(self, job_id: int) -> ScanJobSnapshot | None: ...

    def load_profile(self, workspace_id: int, profile_id: int | None) -> ScanProfile | None: ...

    def mark_running(self, job_id: int, at: datetime) -> None: ...

    def mark_failed(self, job_id: int, failure: JobFailure, at: datetime) -> None: ...

    def mark_done(self, job_id: int, completion: JobCompletion, at: datetime) -> None: ...

    def mark_analyzing(self, job_id: int) -> None: ...

    def write_progress(self, job_id: int, progress_json: str) -> None: ...

    def suppressed_fingerprints(self, workspace_id: int) -> set[str]: ...

    def compliance_rows(self, workspace_id: int) -> list[dict[str, Any]]: ...

    def save_findings(self, job: ScanJobSnapshot, findings: list[ProcessedFinding]) -> None: ...

    def delete_ephemeral_credential(self, job: ScanJobSnapshot) -> None: ...


class SqlScanJobRepository:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def load_job(self, job_id: int) -> ScanJobSnapshot | None:
        with self._session_factory() as db:
            row = db.get(models.ScanJob, job_id)
            if row is None:
                return None
            return ScanJobSnapshot(
                id=row.id,
                workspace_id=row.workspace_id,
                target=row.target,
                scan_type=row.scan_type or "internal",
                profile_id=row.profile_id,
                meta=_json_object(row.meta_json),
                created_at=_utc(row.created_at),
            )

    def load_profile(self, workspace_id: int, profile_id: int | None) -> ScanProfile | None:
        if profile_id is None:
            return None
        with self._session_factory() as db:
            row = (
                db.query(models.Profile)
                .filter(models.Profile.id == profile_id, models.Profile.workspace_id == workspace_id)
                .first()
            )
            return ScanProfile.from_json(row.plugin_selection_json, row.options_json) if row else None

    def mark_running(self, job_id: int, at: datetime) -> None:
        # Stamped here, not at creation: the stale-job watchdog must measure how
        # long the job has been running, not how long it waited in the queue.
        self._update_job(job_id, status="running", started_at=at)

    def mark_failed(self, job_id: int, failure: JobFailure, at: datetime) -> None:
        self._update_job(job_id, status="failed", finished_at=at, meta_json=json.dumps(failure.to_meta()))

    def mark_done(self, job_id: int, completion: JobCompletion, at: datetime) -> None:
        self._update_job(job_id, status="done", finished_at=at, meta_json=json.dumps(completion.to_meta()))

    def mark_analyzing(self, job_id: int) -> None:
        self._update_job(job_id, status="analyzing")

    def write_progress(self, job_id: int, progress_json: str) -> None:
        self._update_job(job_id, meta_json=progress_json)

    def suppressed_fingerprints(self, workspace_id: int) -> set[str]:
        with self._session_factory() as db:
            rows = (
                db.query(models.SuppressedFinding.fingerprint)
                .filter(models.SuppressedFinding.workspace_id == workspace_id)
                .all()
            )
            return {row.fingerprint for row in rows}

    def compliance_rows(self, workspace_id: int) -> list[dict[str, Any]]:
        with self._session_factory() as db:
            paths = [
                row.path
                for row in db.query(models.CveDataset.path).filter(
                    models.CveDataset.workspace_id == workspace_id,
                    models.CveDataset.kind == "compliance_map",
                    models.CveDataset.enabled.is_(True),
                )
            ]
        # load_json logs unreadable files and returns an empty list for them.
        return [row for path in paths for row in load_json(path)]

    def save_findings(self, job: ScanJobSnapshot, findings: list[ProcessedFinding]) -> None:
        with self._session_factory() as db:
            db.add_all(_finding_row(job, finding) for finding in findings)
            db.commit()

    def delete_ephemeral_credential(self, job: ScanJobSnapshot) -> None:
        credential_id = job.ephemeral_credential_id
        if credential_id is None:
            return
        with self._session_factory() as db:
            deleted = (
                db.query(models.Credential)
                .filter(models.Credential.id == credential_id, models.Credential.workspace_id == job.workspace_id)
                .delete()
            )
            db.commit()
        logger.info("Ephemeral cleanup: %d credential(s) #%d removed after job #%d", deleted, credential_id, job.id)

    def _update_job(self, job_id: int, **values: Any) -> None:
        with self._session_factory() as db:
            db.query(models.ScanJob).filter(models.ScanJob.id == job_id).update(values)
            db.commit()


class SqlIntegrationSource:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def enabled_integrations(self, workspace_id: int) -> list[Integration]:
        with self._session_factory() as db:
            rows = (
                db.query(models.Integration)
                .filter(models.Integration.workspace_id == workspace_id, models.Integration.enabled.is_(True))
                .all()
            )
            integrations = []
            for row in rows:
                config = _json_object(row.config_json)
                if not config:
                    logger.warning("Integration #%d (%s) has no valid config — skipped", row.id, row.provider)
                    continue
                integrations.append(Integration(provider=row.provider, config=config))
            return integrations

    def notification_preferences(self, workspace_id: int) -> dict[str, Any]:
        with self._session_factory() as db:
            return notification_preferences(db, workspace_id)


def _finding_row(job: ScanJobSnapshot, finding: ProcessedFinding) -> models.Finding:
    return models.Finding(
        workspace_id=job.workspace_id,
        job_id=job.id,
        target=job.target,
        plugin_id=finding.plugin_id,
        title=_without_nul(finding.title),
        severity=finding.severity.value,
        description=_without_nul(finding.description),
        remediation=_without_nul(finding.remediation),
        references_json=json.dumps(finding.references),
        evidence=_without_nul(finding.evidence),
        fingerprint=finding.fingerprint,
        cvss_base=finding.cvss,
        risk_score=finding.risk_score,
        confidence=finding.confidence,
        sla_days=finding.sla_days,
        compliance_json=json.dumps(finding.compliance) if finding.compliance else None,
        is_kev=finding.is_kev,
        device_id=finding.device_id,
    )


def _utc(moment: datetime | None) -> datetime | None:
    """Columns are UTC; SQLite returns them without timezone, Postgres with."""
    if moment is None or moment.tzinfo is not None:
        return moment
    return moment.replace(tzinfo=timezone.utc)


def _without_nul(text: str) -> str:
    """PostgreSQL text columns reject NUL bytes."""
    return text.replace("\x00", "")


def _json_object(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}
