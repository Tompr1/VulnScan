"""
ProbeGateway — what a probe may do on the platform, and nothing more.

    enroll (one-time token) -> probe id + secret
    authenticate             -> the probe, bound to ONE client
    next_assignment          -> claim the oldest of the client's jobs routed
                                to probes, and its assignment
    progress                 -> store the progress; tells the probe to stop
                                when a user cancelled the job
    report                   -> queue the report for finalization by a worker
    reference data           -> datasets and CVE records the plugins read

Every job operation checks that the job belongs to the probe's client AND
was claimed by this probe; anything else looks like an unknown job.

The HTTP routes (``app.api.routes_probe_agent``) only translate.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.job_queue import ScanReportQueue
from app.cve.cpe import ProductKey
from app.cve.dataset_loader import load_json
from app.cve.reference_datasets import enabled_dataset_paths
from app.cve.sql_catalog import SqlCveCatalog, SqlSyncStateStore
from app.db import models
from app.probes import events
from app.probes.placement import PROBE
from app.probes.registry import ProbeRegistry
from app.scan_jobs.assigner import JobAssigner, JobNotReady
from app.scan_jobs.assignment import ScanAssignment, ScanReport
from app.scan_jobs.outcome import JobStatus
from app.scan_jobs.repository import SqlScanJobRepository
from app.scanner.cancellation import CancellationSignal

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

# Datasets the plugins read through ReferenceData.datasets(kind).
PROBE_DATASET_KINDS = ("cisa_kev", "cms_cve_map", "osv", "cvedetails_cvss", "nvd_cpe_cve")
MAX_PRODUCTS_PER_LOOKUP = 5000
MAX_PROGRESS_BYTES = 64 * 1024
MAX_REPORT_FINDINGS = 50_000
# Jobs looked at per claim attempt: another probe of the client may take some.
_CLAIM_CANDIDATES = 5


class UnknownJob(LookupError):
    """Not a job of this probe (other client, other probe, not running)."""


class InvalidMessage(ValueError):
    pass


class UnknownDataset(LookupError):
    pass


@dataclass(frozen=True)
class ProbeIdentity:
    id: int
    workspace_id: int
    name: str


@dataclass(frozen=True)
class Dataset:
    etag: str
    content: list[list[Any]]


class ProbeGateway:
    def __init__(
        self,
        session_factory: SessionFactory,
        assigner: JobAssigner,
        reports: ScanReportQueue,
        cancellation: CancellationSignal,
        clock: Callable[[], datetime],
        enrollment_ttl: timedelta,
        load_dataset: Callable[[str], Any] = load_json,
    ) -> None:
        self._session_factory = session_factory
        self._assigner = assigner
        self._reports = reports
        self._cancellation = cancellation
        self._clock = clock
        self._enrollment_ttl = enrollment_ttl
        self._load_dataset = load_dataset
        self._jobs = SqlScanJobRepository(session_factory)

    # ── Identity ─────────────────────────────────────────────────────────

    def enroll(self, token: str, hostname: str, version: str, ip: str) -> tuple[ProbeIdentity, str]:
        """Raises :class:`app.probes.registry.EnrollmentError`."""
        with self._session_factory() as db:
            probe, secret = self._registry(db).enroll(token, self._clock(), hostname, version, ip)
            logger.info("Probe #%d (%s) of client #%d enrolled from %s", probe.id, probe.name, probe.workspace_id, ip)
            return _identity(probe), secret

    def authenticate(self, authorization: str | None, ip: str, version: str | None = None) -> ProbeIdentity | None:
        with self._session_factory() as db:
            registry = self._registry(db)
            probe = registry.authenticate(authorization)
            if probe is None:
                return None
            registry.seen(probe, self._clock(), ip, version=version)
            return _identity(probe)

    def heartbeat(self, probe: ProbeIdentity, ip: str, hostname: str | None, version: str | None,
                  image: str | None = None, appliance_version: str | None = None) -> None:
        with self._session_factory() as db:
            row = db.get(models.Probe, probe.id)
            if row is not None:
                self._registry(db).seen(row, self._clock(), ip, hostname, version, image, appliance_version)

    # ── Jobs ─────────────────────────────────────────────────────────────

    def next_assignment(self, probe: ProbeIdentity) -> ScanAssignment | None:
        """Claims the client's oldest job waiting for a probe. A job that
        cannot run (profile deleted…) is failed through a report and the
        next one is tried."""
        while (job_id := self._claim(probe)) is not None:
            job = self._jobs.load_job(job_id)
            if job is None:
                continue
            try:
                profile = self._assigner.profile_for(job)
                return self._assigner.assignment_for(job, profile)
            except JobNotReady as unready:
                self._reports.enqueue_report(job_id, ScanReport.failed(job_id, unready.failure).to_dict())
                self._record(probe, events.JOB_REFUSED, unready.failure.error, job_id)
        return None

    def progress(self, probe: ProbeIdentity, job_id: int, document: Any) -> bool:
        """Stores the progress document; True when the probe must stop."""
        if not isinstance(document, dict) or not isinstance(document.get("progress"), dict):
            raise InvalidMessage("Expected a progress document: {\"progress\": {...}}")
        text = json.dumps(document)
        if len(text) > MAX_PROGRESS_BYTES:
            raise InvalidMessage("Progress document too large")
        self._require_own_running_job(probe, job_id)
        self._jobs.write_progress(job_id, text)
        return self._cancellation.consume(job_id)

    def report(self, probe: ProbeIdentity, job_id: int, data: Any) -> None:
        """Validates the report and queues its finalization."""
        try:
            report = ScanReport.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise InvalidMessage(f"Unreadable report: {exc}") from exc
        if report.job_id != job_id:
            raise InvalidMessage("The report names another job")
        if len(report.findings) > MAX_REPORT_FINDINGS:
            raise InvalidMessage(f"Too many findings (limit {MAX_REPORT_FINDINGS})")
        self._require_own_running_job(probe, job_id)
        self._reports.enqueue_report(job_id, report.to_dict())
        logger.info("Report of job #%d from probe #%d queued (%d findings)", job_id, probe.id, len(report.findings))
        outcome = f"failed: {report.failure.error}" if report.failure else f"{len(report.findings)} findings"
        self._record(probe, events.REPORT_RECEIVED, outcome, job_id)

    # ── Reference data ───────────────────────────────────────────────────

    def reference_status(self) -> dict[str, Any]:
        with self._session_factory() as db:
            etags = {kind: _etag(enabled_dataset_paths(db, kind)) for kind in PROBE_DATASET_KINDS}
        complete = SqlSyncStateStore(self._session_factory).load().full_import_done
        return {"cve_catalog_complete": complete, "datasets": etags}

    def dataset(self, kind: str) -> Dataset:
        if kind not in PROBE_DATASET_KINDS:
            raise UnknownDataset(kind)
        with self._session_factory() as db:
            paths = enabled_dataset_paths(db, kind)
        return Dataset(_etag(paths), [self._load_dataset(path) for path in paths])

    def cve_records(self, products: Any) -> list[dict[str, Any]]:
        """Records of the platform's CVE catalog (database) for these
        (vendor, product) pairs."""
        keys = _product_keys(products)
        records = SqlCveCatalog(self._session_factory).records_for(keys)
        return [record.to_flattened() for record in records]

    # ── Internals ────────────────────────────────────────────────────────

    def _registry(self, db: Session) -> ProbeRegistry:
        return ProbeRegistry(db, self._enrollment_ttl)

    def _claim(self, probe: ProbeIdentity) -> int | None:
        with self._session_factory() as db:
            candidates = [
                job_id for (job_id,) in db.query(models.ScanJob.id)
                .filter(
                    models.ScanJob.workspace_id == probe.workspace_id,
                    models.ScanJob.status == JobStatus.QUEUED.value,
                    models.ScanJob.runs_on == PROBE,
                )
                .order_by(models.ScanJob.created_at, models.ScanJob.id)
                .limit(_CLAIM_CANDIDATES)
            ]
            for job_id in candidates:
                # Conditional: of two probes asking at once, one gets the job.
                claimed = (
                    db.query(models.ScanJob)
                    .filter(models.ScanJob.id == job_id, models.ScanJob.status == JobStatus.QUEUED.value)
                    .update({"status": JobStatus.RUNNING.value, "started_at": self._clock(), "probe_id": probe.id})
                )
                db.commit()
                if claimed == 1:
                    logger.info("Probe #%d claimed job #%d", probe.id, job_id)
                    job = db.get(models.ScanJob, job_id)
                    detail = f"{job.scan_type or 'internal'} scan of {job.target}" if job else ""
                    events.record(db, db.get(models.Probe, probe.id), events.JOB_CLAIMED, self._clock(), detail, job_id)
                    db.commit()
                    return job_id
        return None

    def _record(self, probe: ProbeIdentity, kind: str, detail: str, job_id: int | None = None) -> None:
        with self._session_factory() as db:
            row = db.get(models.Probe, probe.id)
            if row is not None:
                events.record(db, row, kind, self._clock(), detail, job_id)
                db.commit()

    def _require_own_running_job(self, probe: ProbeIdentity, job_id: int) -> None:
        with self._session_factory() as db:
            owned = (
                db.query(models.ScanJob.id)
                .filter(
                    models.ScanJob.id == job_id,
                    models.ScanJob.workspace_id == probe.workspace_id,
                    models.ScanJob.probe_id == probe.id,
                    models.ScanJob.status == JobStatus.RUNNING.value,
                )
                .first()
            )
        if owned is None:
            raise UnknownJob(job_id)


def _identity(probe: models.Probe) -> ProbeIdentity:
    return ProbeIdentity(probe.id, probe.workspace_id, probe.name)


def _etag(paths: Iterable[str]) -> str:
    """Changes when a dataset is added, removed, or its file rewritten."""
    parts = []
    for path in paths:
        try:
            stat = os.stat(path)
            parts.append(f"{path}:{stat.st_size}:{stat.st_mtime_ns}")
        except OSError:
            parts.append(f"{path}:missing")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _product_keys(products: Any) -> set[ProductKey]:
    if not isinstance(products, list):
        raise InvalidMessage("Expected a list of [vendor, product] pairs")
    if len(products) > MAX_PRODUCTS_PER_LOOKUP:
        raise InvalidMessage(f"Too many products (limit {MAX_PRODUCTS_PER_LOOKUP})")
    keys = set()
    for item in products:
        if not (isinstance(item, list) and len(item) == 2 and all(isinstance(x, str) and x for x in item)):
            raise InvalidMessage("Each product is a [vendor, product] pair of strings")
        keys.add((item[0].lower(), item[1].lower()))
    return keys
