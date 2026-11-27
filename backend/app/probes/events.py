"""
The history of each probe, for the MSP: when it was created and enrolled,
which jobs it took and reported, when it went offline and came back, which
image it ran. Rows are only ever added.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.db import models

CREATED = "created"
TOKEN_RENEWED = "token_renewed"
ENROLLED = "enrolled"
REVOKED = "revoked"
JOB_CLAIMED = "job_claimed"
JOB_REFUSED = "job_refused"
REPORT_RECEIVED = "report_received"
IMAGE_CHANGED = "image_changed"
OFFLINE = "offline"
ONLINE = "online"
UPDATE_REQUESTED = "update_requested"
UPDATE_STARTED = "update_started"
UPDATE_DONE = "update_done"
UPDATE_FAILED = "update_failed"

_MAX_DETAIL = 1000


def record(db: Session, probe: models.Probe, kind: str, at: datetime, detail: str = "", job_id: int | None = None) -> None:
    """Adds the event to the session; the caller commits."""
    db.add(models.ProbeEvent(
        probe_id=probe.id, workspace_id=probe.workspace_id, kind=kind, job_id=job_id,
        detail=detail[:_MAX_DETAIL], at=at,
    ))


def history(db: Session, probe_id: int, limit: int = 200) -> list[models.ProbeEvent]:
    """Newest first."""
    return (
        db.query(models.ProbeEvent)
        .filter(models.ProbeEvent.probe_id == probe_id)
        .order_by(models.ProbeEvent.at.desc(), models.ProbeEvent.id.desc())
        .limit(limit)
        .all()
    )
