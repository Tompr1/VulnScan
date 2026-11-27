"""
Scan job submission — creates a job row and hands it to the task queue.

Used by the HTTP API; raises domain exceptions that the routes translate into
HTTP responses.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.job_queue import QueueUnavailableError, ScanJobQueue
from app.db import models
from app.scan_jobs import network_scope
from app.scan_jobs.assignment import INVENTORY_CONNECTION_KEY

logger = logging.getLogger(__name__)

QUEUE_DOWN_DETAIL = (
    "Could not submit the scan job to the task queue. The Redis worker may be "
    "down or unreachable. Check that the 'worker' container is running."
)


class ProfileNotFoundError(LookupError):
    pass


class AssetNotFoundError(LookupError):
    pass


class JobNotFoundError(LookupError):
    pass


class ScanJobSubmission:
    def __init__(self, db: Session, queue: ScanJobQueue) -> None:
        self._db = db
        self._queue = queue

    def submit(
        self,
        workspace_id: int,
        target: str,
        profile_id: int,
        scan_type: str,
        created_by_user_id: int | None,
        asset_id: int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> models.ScanJob:
        """Create and enqueue a scan job.

        Raises ProfileNotFoundError / AssetNotFoundError when they are not in
        the workspace, NetworkScanRefused for an internal scan the client's
        probe cannot run now, and QueueUnavailableError when the job could
        not be queued (the job is then saved as failed).
        """
        self._require_profile(workspace_id, profile_id)
        if asset_id is not None:
            self._require_asset(workspace_id, asset_id)
        network_scope.check_scan(self._db, workspace_id, scan_type, target, datetime.now(timezone.utc))
        job = models.ScanJob(
            workspace_id=workspace_id,
            target=target,
            profile_id=profile_id,
            asset_id=asset_id,
            status="queued",
            scan_type=scan_type,
            meta_json=json.dumps(meta) if meta else None,
            created_by_user_id=created_by_user_id,
        )
        return self._save_and_enqueue(job)

    def submit_inventory(
        self,
        connection: models.InventoryConnection,
        created_by_user_id: int | None,
        requested_at: datetime,
    ) -> models.ScanJob:
        """Queue the collection of a fleet manager connection's inventory."""
        connection.last_sync_requested_at = requested_at
        connection.last_sync_status = "queued"
        return self._save_and_enqueue(models.ScanJob(
            workspace_id=connection.workspace_id,
            target=f"{connection.provider}:{connection.name}"[:512],
            profile_id=None,
            status="queued",
            scan_type="inventory",
            meta_json=json.dumps({INVENTORY_CONNECTION_KEY: connection.id}),
            created_by_user_id=created_by_user_id,
        ))

    def rescan(self, workspace_id: int, job_id: int) -> models.ScanJob:
        """Queue a new job with the target, profile and type of an existing one."""
        original = self._db.query(models.ScanJob).filter(
            models.ScanJob.workspace_id == workspace_id, models.ScanJob.id == job_id
        ).first()
        if original is None:
            raise JobNotFoundError(job_id)
        scan_type = original.scan_type or "internal"
        network_scope.check_scan(self._db, workspace_id, scan_type, original.target, datetime.now(timezone.utc))
        return self._save_and_enqueue(models.ScanJob(
            workspace_id=workspace_id,
            target=original.target,
            profile_id=original.profile_id,
            status="queued",
            scan_type=scan_type,
        ))

    def _save_and_enqueue(self, job: models.ScanJob) -> models.ScanJob:
        self._db.add(job)
        self._db.commit()
        self._db.refresh(job)
        try:
            self._queue.enqueue_scan(job.id)
        except QueueUnavailableError as exc:
            job.status = "failed"
            job.meta_json = json.dumps({
                "error": f"Failed to enqueue: {exc}",
                "error_type": "queue",
                "error_detail": QUEUE_DOWN_DETAIL,
            })
            self._db.commit()
            raise
        logger.info("Enqueued scan job #%d target=%s type=%s", job.id, job.target, job.scan_type)
        return job

    def _require_profile(self, workspace_id: int, profile_id: int) -> None:
        exists = self._db.query(models.Profile.id).filter(
            models.Profile.workspace_id == workspace_id, models.Profile.id == profile_id
        ).first()
        if exists is None:
            raise ProfileNotFoundError(profile_id)

    def _require_asset(self, workspace_id: int, asset_id: int) -> None:
        exists = self._db.query(models.Asset.id).filter(
            models.Asset.workspace_id == workspace_id, models.Asset.id == asset_id
        ).first()
        if exists is None:
            raise AssetNotFoundError(asset_id)
