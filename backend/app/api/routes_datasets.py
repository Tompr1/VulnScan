import json
import logging
import os
import uuid

import redis
from fastapi import APIRouter, Depends, HTTPException, File, Query, UploadFile
from pydantic import BaseModel
from rq import Queue
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_global_admin, require_shared_reader
from app.core.config import settings
from app.core.job_queue import get_job_queue
from app.cve.reference_datasets import (
    REFRESH_LOCK_KEY, REFRESH_STATUS_KEY, clear_abandoned_refresh, latest_dataset_path,
)
from app.db import models
from app.threat_intel import aggregator as _ti_aggregator

# The reference datasets are shared by every client: everyone reads them,
# only a global admin changes or refreshes them.
router = APIRouter(prefix="/datasets", tags=["datasets"])

logger = logging.getLogger("v0cday.api.datasets")

# Dataset kinds the Threat Intel table is built from.
_TI_FEEDER_KINDS = set(_ti_aggregator.FEEDER_KINDS)

# Canonical dataset file paths — these must NEVER be deleted via the UI
# because they are the stable files the system writes during refresh.
_CANONICAL_PATHS = {
    "/data/cve/nvd_cpe_cve.json",
    "/data/cve/cisa_kev.json",
    "/data/cve/epss.json",
    "/data/cve/vendor_advisories.json",
    "/data/cve/cvedetails_cvss.json",
    "/data/cve/cms_cve_map.json",
    "/data/cve/compliance_map.json",
}


# Fields a global admin may change on a dataset record.
_EDITABLE_FIELDS = {"name", "kind", "path", "enabled"}


def _queue_ti_rebuild() -> None:
    """Best-effort: rebuild the Threat Intel table in the datasets worker (the
    scheduler also notices a changed dataset within a minute)."""
    try:
        _ti_aggregator.request_rebuild(_redis_conn(), get_job_queue().enqueue_threat_intel_rebuild)
    except Exception as exc:
        logger.warning("Threat Intel rebuild not queued: %s", exc)


# ── Browse dataset contents ─────────────────────────────────────────────────

@router.get("/browse/{kind}")
def browse_dataset(
    kind: str,
    q: str = Query("", description="Search filter"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user=Depends(require_shared_reader("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Return paginated contents of a dataset file."""
    path = latest_dataset_path(db, kind)
    if path is None:
        raise HTTPException(404, f"No enabled dataset of kind '{kind}'")
    if not os.path.isfile(path):
        raise HTTPException(404, f"Dataset file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        raise HTTPException(500, f"Failed to read dataset: {e}")

    # Normalize to list of records
    if kind == "cvedetails_cvss":
        # Dict keyed by CVE-ID → convert to list
        records = [{"cve": k, **v} for k, v in raw.items()] if isinstance(raw, dict) else raw
    elif kind == "compliance_map":
        # Has metadata wrapper
        records = raw.get("mappings", []) if isinstance(raw, dict) else raw
    else:
        records = raw if isinstance(raw, list) else []

    # Search filter
    if q:
        ql = q.lower()
        filtered = []
        for r in records:
            if any(ql in str(v).lower() for v in r.values()):
                filtered.append(r)
        records = filtered

    total = len(records)
    start = (page - 1) * per_page
    end = start + per_page
    page_records = records[start:end]

    # For compliance_map, also include control_descriptions and frameworks metadata
    extra = {}
    if kind == "compliance_map" and isinstance(raw, dict):
        extra["control_descriptions"] = raw.get("control_descriptions", {})
        extra["frameworks"] = raw.get("frameworks", [])
        extra["version"] = raw.get("version", "")

    return {
        "kind": kind,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, -(-total // per_page)),
        "records": page_records,
        **extra,
    }


class DatasetCreate(BaseModel):
    name: str
    kind: str
    path: str
    enabled: bool = True


@router.get("")
def list_datasets(user=Depends(require_shared_reader("admin", "analyst", "viewer")), db: Session = Depends(get_db)):
    ds = db.query(models.CveDataset).order_by(models.CveDataset.id).all()
    return [
        {
            "id": d.id,
            "name": d.name,
            "kind": d.kind,
            "path": d.path,
            "enabled": d.enabled,
        }
        for d in ds
    ]


@router.post("")
def create_dataset(
    body: DatasetCreate,
    user=Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    d = models.CveDataset(
        name=body.name,
        kind=body.kind,
        path=body.path,
        enabled=body.enabled,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"id": d.id}


@router.post("/upload")
def upload_dataset(
    file: UploadFile = File(...),
    kind: str = Query(...),
    name: str = Query(""),
    user: dict = Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    if not name:
        name = kind

    # A plain def: validating a large file runs in a worker thread, not on
    # the event loop every other request waits on.
    content = file.file.read()
    try:
        json.loads(content)
    except Exception:
        raise HTTPException(400, "File is not valid JSON")

    upload_dir = "/data/cve"
    os.makedirs(upload_dir, exist_ok=True)
    filename = f"{kind}_{uuid.uuid4().hex[:8]}.json"
    filepath = os.path.join(upload_dir, filename)

    with open(filepath, "wb") as f:
        f.write(content)

    d = models.CveDataset(
        name=name,
        kind=kind,
        path=filepath,
        enabled=True,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    if kind in _TI_FEEDER_KINDS:
        _queue_ti_rebuild()
    return {"dataset_id": d.id, "path": filepath}


@router.patch("/{ds_id}")
def update_dataset(
    ds_id: int,
    body: dict,
    user=Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    d = db.get(models.CveDataset, ds_id)
    if not d:
        raise HTTPException(status_code=404, detail="Not found")
    for k, v in body.items():
        if k in _EDITABLE_FIELDS:
            setattr(d, k, v)
    db.commit()
    if d.kind in _TI_FEEDER_KINDS and "enabled" in body:
        _queue_ti_rebuild()
    return {"ok": True}


@router.patch("/{ds_id}/toggle")
def toggle_dataset(
    ds_id: int,
    user=Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    d = db.get(models.CveDataset, ds_id)
    if not d:
        raise HTTPException(status_code=404, detail="Not found")
    d.enabled = not d.enabled
    db.commit()
    if d.kind in _TI_FEEDER_KINDS:
        _queue_ti_rebuild()
    return {"ok": True, "enabled": d.enabled}


@router.delete("/{ds_id}")
def delete_dataset(
    ds_id: int,
    user=Depends(require_global_admin),
    db: Session = Depends(get_db),
):
    d = db.get(models.CveDataset, ds_id)
    if not d:
        raise HTTPException(status_code=404, detail="Not found")

    kind = d.kind

    # Only delete the file if no other dataset record shares the same path
    # and the file is NOT a canonical dataset file (those are managed by the
    # refresh worker and must never be removed via the UI).
    if d.path and os.path.isfile(d.path) and d.path not in _CANONICAL_PATHS:
        other = (
            db.query(models.CveDataset)
            .filter(
                models.CveDataset.id != d.id,
                models.CveDataset.path == d.path,
            )
            .first()
        )
        if not other:
            try:
                os.remove(d.path)
            except Exception:
                pass

    db.delete(d)
    db.commit()
    if kind in _TI_FEEDER_KINDS:
        _queue_ti_rebuild()
    return {"ok": True}


# ── Dataset Refresh ─────────────────────────────────────────────────────────

_VALID_KINDS = {"nvd_cpe_cve", "cisa_kev", "epss", "vendor_advisories", "cvedetails_cvss", "cms_cve_map", "compliance_map"}


def _redis_conn():
    return redis.Redis.from_url(settings.REDIS_URL)


def _job_status(r):
    """RQ status of a job id ("started", "failed"…), None if unknown."""
    from rq.exceptions import NoSuchJobError
    from rq.job import Job

    def status(job_id: str) -> str | None:
        try:
            value = Job.fetch(job_id, connection=r).get_status()
        except NoSuchJobError:
            return None
        return getattr(value, "value", value)

    return status


@router.post("/refresh")
def refresh_datasets(
    body: dict = {},
    user: dict = Depends(require_global_admin),
):
    from app.worker_tasks import run_dataset_refresh

    kinds = None
    if "kind" in body:
        kinds = [body["kind"]]
    elif "kinds" in body:
        kinds = body["kinds"]

    if kinds:
        invalid = set(kinds) - _VALID_KINDS
        if invalid:
            raise HTTPException(400, f"Invalid kinds: {invalid}")

    r = _redis_conn()
    clear_abandoned_refresh(r, _job_status(r))
    if r.exists(REFRESH_LOCK_KEY):
        raise HTTPException(409, "A dataset refresh is already running")

    q = Queue("datasets", connection=r)
    q.enqueue(run_dataset_refresh, kinds, job_timeout=7200)
    if not kinds or "nvd_cpe_cve" in kinds:
        # The full NVD history lives in the database catalog (app/cve/nvd_sync.py).
        get_job_queue().enqueue_cve_catalog_sync()
    return {"status": "queued", "kinds": kinds or list(_VALID_KINDS)}


@router.get("/refresh/status")
def refresh_status(
    user: dict = Depends(require_shared_reader("admin", "analyst", "viewer")),
):
    r = _redis_conn()
    clear_abandoned_refresh(r, _job_status(r))
    data = r.get(REFRESH_STATUS_KEY)
    if not data:
        return {"status": "idle"}
    return json.loads(data)


@router.post("/refresh/cancel")
def cancel_refresh(
    user: dict = Depends(require_global_admin),
):
    r = _redis_conn()
    r.delete(REFRESH_LOCK_KEY)
    data = r.get(REFRESH_STATUS_KEY)
    if data:
        state = json.loads(data)
        state["status"] = "cancelled"
        r.setex(REFRESH_STATUS_KEY, 3600, json.dumps(state))
    return {"ok": True}
