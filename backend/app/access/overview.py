"""
What the client picker shows of each client a user may open: its name, the
user's role there, and a few counters to tell where to look first.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection
from datetime import datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.access.domain import UserAccess
from app.db import models

COUNTED_SEVERITIES = ("critical", "high")


class SqlClientOverview:
    def __init__(self, db: Session) -> None:
        self._db = db

    def clients_of(self, access: UserAccess) -> list[dict[str, Any]]:
        """The clients this user may open, by name, with their open findings."""
        client_ids = access.client_ids
        if not client_ids:
            return []
        names = dict(
            self._db.query(models.Workspace.id, models.Workspace.name).filter(models.Workspace.id.in_(client_ids))
        )
        counts = self._open_findings(client_ids)
        kev = self._open_kev(client_ids)
        last_scans = self._last_scans(client_ids)
        clients = [
            {
                "id": client_id,
                "name": names[client_id],
                "role": access.role_on(client_id).value,
                "open_findings": {severity: counts[client_id][severity] for severity in COUNTED_SEVERITIES},
                "open_kev": kev.get(client_id, 0),
                "last_scan_at": _iso(last_scans.get(client_id)),
            }
            for client_id in client_ids
            if client_id in names
        ]
        return sorted(clients, key=lambda client: client["name"].lower())

    def _open_findings(self, client_ids: Collection[int]) -> dict[int, dict[str, int]]:
        counts: dict[int, dict[str, int]] = defaultdict(lambda: dict.fromkeys(COUNTED_SEVERITIES, 0))
        rows = (
            self._db.query(models.Finding.workspace_id, models.Finding.severity, func.count())
            .filter(
                models.Finding.workspace_id.in_(client_ids),
                models.Finding.status == "open",
                models.Finding.severity.in_(COUNTED_SEVERITIES),
            )
            .group_by(models.Finding.workspace_id, models.Finding.severity)
        )
        for client_id, severity, count in rows:
            counts[client_id][severity] = count
        return counts

    def _open_kev(self, client_ids: Collection[int]) -> dict[int, int]:
        rows = (
            self._db.query(models.Finding.workspace_id, func.count())
            .filter(
                models.Finding.workspace_id.in_(client_ids),
                models.Finding.status == "open",
                models.Finding.is_kev.is_(True),
            )
            .group_by(models.Finding.workspace_id)
        )
        return dict(rows.all())

    def _last_scans(self, client_ids: Collection[int]) -> dict[int, datetime]:
        rows = (
            self._db.query(models.ScanJob.workspace_id, func.max(models.ScanJob.finished_at))
            .filter(models.ScanJob.workspace_id.in_(client_ids), models.ScanJob.status == "done")
            .group_by(models.ScanJob.workspace_id)
        )
        return dict(rows.all())


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None
