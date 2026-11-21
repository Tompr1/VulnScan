import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.api.schemas.scan import (
    CreateJobRequest,
    CreateProfileRequest,
    CreateScheduleRequest,
    SuppressFindingRequest,
    UpdateProfileRequest,
)
from app.core.config import settings
from app.core.job_queue import QueueUnavailableError, ScanJobQueue, get_job_queue
from app.db import models
from app.risk.cvss_engine import cvss_baseline_from_severity
from app.scan_jobs.submission import (
    AssetNotFoundError,
    JobNotFoundError,
    ProfileNotFoundError,
    ScanJobSubmission,
)
from app.scanner.cancellation import CancellationSignal, RedisCancellationSignal
from app.scanner.plugins.loader import builtin_registry

logger = logging.getLogger("vulnscan.scan")

router = APIRouter(prefix="/scan", tags=["scan"])


def get_cancellation_signal() -> CancellationSignal:
    return RedisCancellationSignal.from_url(settings.REDIS_URL)


def _resolve_user_id(db: Session, claims: dict) -> int | None:
    """Fallback for old JWT tokens missing the 'uid' claim."""
    email = claims.get("sub")
    if not email:
        return None
    u = db.query(models.User.id).filter(models.User.email == email).first()
    return u.id if u else None


# ─── Available Plugins ────────────────────────────────────────────────────────

@router.get("/plugins")
def list_plugins(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Return all available scanner plugins with their metadata."""
    result = [
        {
            "plugin_id": plugin.meta.plugin_id,
            "name": plugin.meta.name,
            "category": plugin.meta.category,
            "enabled_by_default": plugin.meta.enabled_by_default,
            "timeout_seconds": plugin.meta.timeout_seconds,
            "depends_on": list(plugin.meta.depends_on),
        }
        for plugin in builtin_registry()
    ]
    result.sort(key=lambda p: (p["category"], p["name"]))
    return {"plugins": result}


# ─── Profiles ─────────────────────────────────────────────────────────────────

@router.post("/profiles", response_model=dict)
def create_profile(
    body: CreateProfileRequest,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    row = models.Profile(
        workspace_id=user["ws"],
        name=body.name,
        plugin_selection_json=body.plugin_selection_text(),
        options_json=body.options_text(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/profiles")
def list_profiles(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(models.Profile)
        .filter(models.Profile.workspace_id == user["ws"])
        .order_by(models.Profile.id.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "plugin_selection_json": r.plugin_selection_json,
            "options_json": r.options_json,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.delete("/profiles/{profile_id}")
def delete_profile(
    profile_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    prof = (
        db.query(models.Profile)
        .filter(
            models.Profile.workspace_id == user["ws"],
            models.Profile.id == profile_id,
        )
        .first()
    )
    if not prof:
        raise HTTPException(404, "profile not found")

    job_count = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.profile_id == profile_id,
        )
        .count()
    )
    if job_count > 0:
        db.query(models.ScanJob).filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.profile_id == profile_id,
        ).update({models.ScanJob.profile_id: None}, synchronize_session="fetch")

    db.delete(prof)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Failed to delete profile #%d: %s", profile_id, e)
        raise HTTPException(500, f"Failed to delete profile: {e}")
    logger.info("Deleted profile #%d (unlinked %d jobs)", profile_id, job_count)
    return {"ok": True, "deleted_profile_id": profile_id, "unlinked_jobs": job_count}


@router.put("/profiles/{profile_id}", response_model=dict)
def update_profile(
    profile_id: int,
    body: UpdateProfileRequest,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    prof = (
        db.query(models.Profile)
        .filter(
            models.Profile.workspace_id == user["ws"],
            models.Profile.id == profile_id,
        )
        .first()
    )
    if not prof:
        raise HTTPException(404, "profile not found")

    if body.name is not None:
        prof.name = body.name
    if "plugin_selection_json" in body.model_fields_set:
        prof.plugin_selection_json = body.plugin_selection_text()
    if "options_json" in body.model_fields_set:
        prof.options_json = body.options_text()

    try:
        db.commit()
        db.refresh(prof)
    except Exception as e:
        db.rollback()
        logger.error("Failed to update profile #%d: %s", profile_id, e)
        raise HTTPException(500, f"Failed to update profile: {e}")

    logger.info("Updated profile #%d (%s)", profile_id, prof.name)
    return {
        "id": prof.id,
        "name": prof.name,
        "plugin_selection_json": prof.plugin_selection_json,
        "options_json": prof.options_json,
        "created_at": prof.created_at.isoformat() if prof.created_at else None,
    }


# ─── Jobs ──────────────────────────────────────────────────────────────────────

@router.post("/jobs")
def create_job(
    body: CreateJobRequest,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
    queue: ScanJobQueue = Depends(get_job_queue),
):
    try:
        job = ScanJobSubmission(db, queue).submit(
            workspace_id=user["ws"],
            target=body.target,
            profile_id=body.profile_id,
            scan_type=body.scan_type,
            asset_id=body.asset_id,
            meta=body.job_meta(),
            created_by_user_id=user.get("uid") or _resolve_user_id(db, user),
        )
    except ProfileNotFoundError:
        raise HTTPException(404, "profile not found")
    except AssetNotFoundError:
        raise HTTPException(400, "asset_id does not match a folder in this workspace")
    except QueueUnavailableError as exc:
        raise HTTPException(503, f"Could not enqueue job: {exc}")

    return {
        "id": job.id,
        "target": job.target,
        "status": job.status,
        "scan_type": job.scan_type,
        "profile_id": job.profile_id,
        "asset_id": job.asset_id,
        "created_at": job.created_at.isoformat() if job.created_at else None,
    }


@router.get("/jobs")
def list_jobs(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.workspace_id == user["ws"])
        .order_by(models.ScanJob.id.desc())
        .all()
    )
    # Build user lookup for created_by display
    user_ids = {r.created_by_user_id for r in rows if r.created_by_user_id}
    user_map = {}
    if user_ids:
        for u in db.query(models.User).filter(models.User.id.in_(user_ids)).all():
            user_map[u.id] = u.email

    return [
        {
            "id": r.id,
            "target": r.target,
            "profile_id": r.profile_id,
            "asset_id": r.asset_id,
            "status": r.status,
            "scan_type": r.scan_type or "internal",
            "created_by": user_map.get(r.created_by_user_id, "").split("@")[0] if r.created_by_user_id else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "meta_json": r.meta_json if r.status == "running" else None,
            "error_info": _extract_error_info(r.meta_json) if r.status == "failed" else None,
        }
        for r in rows
    ]


def _extract_error_info(meta_json: str | None) -> dict | None:
    if not meta_json:
        return None
    try:
        meta = json.loads(meta_json)
        if isinstance(meta, dict) and "error" in meta:
            return {
                "error": meta.get("error", "Unknown error"),
                "error_type": meta.get("error_type", "unknown"),
                "error_detail": meta.get("error_detail", ""),
            }
    except json.JSONDecodeError:
        return None
    return None


@router.get("/jobs/{job_id}")
def job_detail(
    job_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    job = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.id == job_id,
        )
        .first()
    )
    if not job:
        raise HTTPException(404, "job not found")

    findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.workspace_id == user["ws"],
            models.Finding.job_id == job_id,
        )
        .order_by(models.Finding.risk_score.desc().nullslast())
        .all()
    )

    error_info = _extract_error_info(job.meta_json) if job.status == "failed" else None

    created_by = None
    if job.created_by_user_id:
        creator = db.query(models.User).filter(models.User.id == job.created_by_user_id).first()
        if creator:
            created_by = creator.email.split("@")[0]

    return {
        "job": {
            "id": job.id,
            "target": job.target,
            "profile_id": job.profile_id,
            "asset_id": job.asset_id,
            "status": job.status,
            "scan_type": job.scan_type or "internal",
            "created_by": created_by,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "meta_json": job.meta_json,
            "error_info": error_info,
        },
        "findings": [
            {
                "id": f.id,
                "plugin_id": f.plugin_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "fingerprint": f.fingerprint,
                "references_json": f.references_json,
                # cvss_base falls back to a severity-derived baseline so the UI
                # doesn't show "—" for plugin findings that aren't tied to a CVE.
                "cvss_base": f.cvss_base if f.cvss_base is not None else cvss_baseline_from_severity(f.severity),
                "risk_score": f.risk_score,
                "confidence": f.confidence,
                "is_kev": f.is_kev,
                "status": f.status,
                "sla_days": f.sla_days,
                "compliance_json": f.compliance_json,
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "device_id": f.device_id,
            }
            for f in findings
        ],
    }


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
    cancellation: CancellationSignal = Depends(get_cancellation_signal),
):
    """Cancel a running or queued scan job."""
    job = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.id == job_id,
        )
        .first()
    )
    if not job:
        raise HTTPException(404, "job not found")
    if job.status not in ("queued", "running"):
        raise HTTPException(400, f"Job is already {job.status}")

    # The scan engine checks this signal before each plugin.
    cancellation.request(job_id)

    # If still queued, cancel immediately
    if job.status == "queued":
        job.status = "cancelled"
        job.meta_json = json.dumps({"cancelled": True, "cancelled_by": user.get("email", "unknown")})
        db.commit()
        logger.info("Cancelled queued job #%d", job_id)
        return {"id": job_id, "status": "cancelled", "message": "Job cancelled (was queued)"}

    # If running, the worker will pick up the cancel flag
    logger.info("Cancel requested for running job #%d", job_id)
    return {"id": job_id, "status": "cancelling", "message": "Cancel signal sent — job will stop after current plugin completes"}


@router.delete("/jobs/{job_id}")
def delete_job(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    job = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.id == job_id,
        )
        .first()
    )
    if not job:
        raise HTTPException(404, "job not found")

    ws_id = user["ws"]

    # Delete AI analyses linked to this job
    db.query(models.AiAnalysis).filter(
        models.AiAnalysis.job_id == job_id,
        models.AiAnalysis.workspace_id == ws_id,
    ).delete()

    db.query(models.Finding).filter(
        models.Finding.job_id == job_id,
        models.Finding.workspace_id == ws_id,
    ).delete()

    db.delete(job)
    db.commit()
    logger.info("Deleted scan job #%d", job_id)

    # Rebuild Neo4j graph from remaining findings
    try:
        from app.graph.neo4j_client import Neo4jClient
        neo = Neo4jClient()
        remaining = (
            db.query(models.Finding)
            .filter(models.Finding.workspace_id == ws_id)
            .all()
        )
        neo.sync_from_findings(ws_id, [
            {
                "target": f.target,
                "cve": f.evidence.split("CVE-")[1].split(" ")[0].split(")")[0] if "CVE-" in (f.evidence or "") else "",
                "plugin_id": f.plugin_id,
                "risk_score": f.risk_score,
            }
            for f in remaining
        ])
        neo.close()
    except Exception as e:
        logger.debug("Neo4j graph sync after delete: %s", e)

    return {"ok": True, "deleted_job_id": job_id}


@router.post("/suppress")
def suppress(
    body: SuppressFindingRequest,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    fp, reason = body.fingerprint, body.reason

    existing = (
        db.query(models.SuppressedFinding)
        .filter(
            models.SuppressedFinding.workspace_id == user["ws"],
            models.SuppressedFinding.fingerprint == fp,
        )
        .first()
    )
    if existing:
        existing.reason = reason
    else:
        row = models.SuppressedFinding(
            workspace_id=user["ws"], fingerprint=fp, reason=reason
        )
        db.add(row)
    db.commit()
    return {"ok": True}

# ─── Rescan ────────────────────────────────────────────────────────────────────

@router.post("/jobs/{job_id}/rescan")
def rescan_job(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
    queue: ScanJobQueue = Depends(get_job_queue),
):
    """Create a new scan job with the same target/profile/type as an existing job."""
    try:
        new_job = ScanJobSubmission(db, queue).rescan(user["ws"], job_id)
    except JobNotFoundError:
        raise HTTPException(404, "job not found")
    except QueueUnavailableError as exc:
        raise HTTPException(503, f"Could not enqueue rescan: {exc}")
    return {
        "id": new_job.id,
        "original_job_id": job_id,
        "target": new_job.target,
        "status": new_job.status,
    }


# ─── Scan History (per host) ──────────────────────────────────────────────────

@router.get("/history/{target:path}")
def scan_history(
    target: str,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Get all scan jobs and finding summaries for a specific target."""
    ws = user["ws"]
    jobs = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == ws,
            models.ScanJob.target == target,
        )
        .order_by(models.ScanJob.created_at.desc())
        .all()
    )

    history = []
    for j in jobs:
        finding_counts = {}
        findings = (
            db.query(models.Finding.severity, models.Finding.id)
            .filter(models.Finding.job_id == j.id, models.Finding.workspace_id == ws)
            .all()
        )
        for f_sev, _ in findings:
            finding_counts[f_sev] = finding_counts.get(f_sev, 0) + 1

        history.append({
            "job_id": j.id,
            "target": j.target,
            "scan_type": j.scan_type or "internal",
            "profile_id": j.profile_id,
            "status": j.status,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
            "severity_counts": finding_counts,
            "total_findings": sum(finding_counts.values()),
        })

    return {"target": target, "scans": history, "total_scans": len(history)}


# ─── Scan Schedules ───────────────────────────────────────────────────────────

@router.get("/schedules")
def list_schedules(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.workspace_id == user["ws"])
        .order_by(models.ScanSchedule.id.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "target": r.target,
            "profile_id": r.profile_id,
            "scan_type": r.scan_type,
            "schedule_type": r.schedule_type or "interval",
            "interval_hours": r.interval_hours,
            "custom_datetime": r.custom_datetime.isoformat() if r.custom_datetime else None,
            "repeat": r.repeat if r.repeat is not None else True,
            "enabled": r.enabled,
            "last_run_at": r.last_run_at.isoformat() if r.last_run_at else None,
            "next_run_at": r.next_run_at.isoformat() if r.next_run_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("/schedules")
def create_schedule(
    body: CreateScheduleRequest,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    if body.schedule_type == "custom":
        next_run = body.custom_datetime
    else:
        next_run = datetime.now(timezone.utc) + timedelta(hours=body.interval_hours)

    sched = models.ScanSchedule(
        workspace_id=user["ws"],
        name=body.display_name,
        target=body.target,
        profile_id=body.profile_id,
        scan_type=body.scan_type,
        schedule_type=body.schedule_type,
        interval_hours=body.interval_hours,
        custom_datetime=body.custom_datetime,
        repeat=body.repeat,
        enabled=body.enabled,
        next_run_at=next_run,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    logger.info("Schedule #%d created: %s %s", sched.id, body.target, body.schedule_type)
    return {"id": sched.id, "name": sched.name, "next_run_at": sched.next_run_at.isoformat() if sched.next_run_at else None}


@router.put("/schedules/{sched_id}/toggle")
def toggle_schedule(
    sched_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    sched = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.workspace_id == user["ws"], models.ScanSchedule.id == sched_id)
        .first()
    )
    if not sched:
        raise HTTPException(404, "schedule not found")
    sched.enabled = not sched.enabled
    db.commit()
    return {"id": sched.id, "enabled": sched.enabled}


@router.delete("/schedules/{sched_id}")
def delete_schedule(
    sched_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    sched = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.workspace_id == user["ws"], models.ScanSchedule.id == sched_id)
        .first()
    )
    if not sched:
        raise HTTPException(404, "schedule not found")
    db.delete(sched)
    db.commit()
    return {"ok": True}

