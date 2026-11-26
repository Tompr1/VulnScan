"""
ProbeWatch — tells each client when its probe goes offline, and when it is
back, once each time.

An enrolled probe calls the platform at least every 30 s (long poll), and
every minute while it scans. Not heard from for PROBE_OFFLINE_ALERT_MINUTES:
"offline" is sent and recorded on the probe (offline_since). Heard from
again: "back online", with how long it was away.

The platform itself may have been down: a probe is only judged on the time
since the platform started, so a restart of the platform does not report
every probe offline.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Protocol

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import models
from app.probes import events
from app.probes.alerts import ProbeStatusAlert
from app.probes.placement import PROBE
from app.probes.registry import ACTIVE
from app.scan_jobs.outcome import JobStatus

logger = logging.getLogger(__name__)


class ProbeStatusNotifier(Protocol):
    def probe_status(self, workspace_id: int, alert: ProbeStatusAlert) -> None: ...


class ProbeWatch:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        notifier: ProbeStatusNotifier,
        clock: Callable[[], datetime],
        offline_after: timedelta,
        probes_url: str | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._notifier = notifier
        self._clock = clock
        self._offline_after = offline_after
        self._probes_url = probes_url
        self._started = clock()

    def check(self) -> list[ProbeStatusAlert]:
        """Records and sends the changes since the last check."""
        now = self._clock()
        alerts: list[tuple[int, ProbeStatusAlert]] = []
        with self._session_factory() as db:
            waiting = dict(
                db.query(models.ScanJob.workspace_id, func.count(models.ScanJob.id))
                .filter(models.ScanJob.status == JobStatus.QUEUED.value, models.ScanJob.runs_on == PROBE)
                .group_by(models.ScanJob.workspace_id)
            )
            for probe in db.query(models.Probe).filter(models.Probe.status == ACTIVE):
                alert = self._change(db, probe, now, waiting.get(probe.workspace_id, 0))
                if alert is not None:
                    alerts.append((probe.workspace_id, alert))
            db.commit()
        for workspace_id, alert in alerts:
            logger.info("Probe #%d is %s", alert.probe_id, alert.state)
            try:
                self._notifier.probe_status(workspace_id, alert)
            except Exception as exc:  # the state is recorded; a failing integration must not stop the watch
                logger.warning("Probe status notification failed: %s", exc)
        return [alert for _, alert in alerts]

    def _change(self, db: Session, probe: models.Probe, now: datetime, waiting_jobs: int) -> ProbeStatusAlert | None:
        seen = _utc(probe.last_seen_at)
        offline_since = _utc(probe.offline_since)
        # Silence counts from the platform's start at the earliest.
        silent_from = max(seen, self._started) if seen else self._started
        silent = now - silent_from > self._offline_after
        if silent and offline_since is None:
            probe.offline_since = now
            events.record(db, probe, events.OFFLINE, now, f"last heard from at {seen.isoformat() if seen else 'never'}")
            return self._alert(db, probe, online=False, since=seen or self._started, now=now, waiting_jobs=waiting_jobs)
        if offline_since is not None and seen is not None and seen > offline_since:
            probe.offline_since = None
            events.record(db, probe, events.ONLINE, now, f"offline since {offline_since.isoformat()}")
            return self._alert(db, probe, online=True, since=offline_since, now=now, waiting_jobs=waiting_jobs)
        return None

    def _alert(self, db: Session, probe: models.Probe, online: bool, since: datetime, now: datetime,
               waiting_jobs: int) -> ProbeStatusAlert:
        client = db.get(models.Workspace, probe.workspace_id)
        return ProbeStatusAlert(
            probe_id=probe.id,
            probe_name=probe.name,
            client_name=client.name if client else f"client #{probe.workspace_id}",
            online=online,
            since=since,
            at=now,
            waiting_jobs=waiting_jobs,
            url=self._probes_url,
        )


def _utc(moment: datetime | None) -> datetime | None:
    if moment is None or moment.tzinfo is not None:
        return moment
    return moment.replace(tzinfo=timezone.utc)
