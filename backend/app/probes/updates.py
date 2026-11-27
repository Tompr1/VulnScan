"""
Updates of probes installed from the source (deploy/probe), asked from Root.

A probe only connects out, so the platform cannot update it: it asks, and
the updater installed on the probe's VM does the work.

    Root "Check for updates"  compare each probe's build (the commit its
                              image was built from) with the platform's own
    Root "Update"             requested: the platform's commit is the target
    probe updater             reads the target in the heartbeat answer, says
                              "running", fetches that commit from the
                              repository (only if it is on the branch it
                              follows), rebuilds, restarts, checks, and says
                              "done" or "failed" (it rolls back on failure)
    the new probe             reports its new build: done, even if the
                              updater's last word was lost

Appliances are not updated this way: they move to the signed image the
platform publishes (PROBE_IMAGE) by themselves.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db import models
from app.probes import events

logger = logging.getLogger(__name__)

REQUESTED, RUNNING, DONE, FAILED = "requested", "running", "done", "failed"
IN_PROGRESS = (REQUESTED, RUNNING)
# What a probe's code looks like next to the platform's, for Root.
CURRENT, OUTDATED, UNKNOWN, UPDATING, APPLIANCE = "current", "outdated", "unknown", "updating", "appliance"

_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
MAX_DETAIL = 2000


class UpdateNotPossible(RuntimeError):
    pass


class NoUpdatePending(LookupError):
    pass


class InvalidUpdateReport(ValueError):
    pass


def clean_build(raw: str | None) -> str | None:
    """A commit id as a probe or the platform states it, or None."""
    value = (raw or "").strip().lower()
    return value if _COMMIT.match(value) else None


def platform_build(env_value: str, file_path: str) -> str | None:
    """The commit the platform runs: PLATFORM_BUILD, else the file
    scripts/deploy.sh writes at each deploy; None when neither says."""
    if clean_build(env_value):
        return clean_build(env_value)
    try:
        with open(file_path, encoding="utf-8") as f:
            return clean_build(f.read())
    except OSError:
        return None


def code_status(probe: models.Probe, platform: str | None) -> str:
    if probe.appliance_version:
        return APPLIANCE
    if probe.update_status in IN_PROGRESS:
        return UPDATING
    build = clean_build(probe.build)
    if not platform or not build:
        return UNKNOWN
    return CURRENT if _same(build, platform) else OUTDATED


def _same(a: str, b: str) -> bool:
    """Equal commits, one possibly abbreviated."""
    return a.startswith(b) or b.startswith(a)


def _utc(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


# ── Root ────────────────────────────────────────────────────────────────────

def request_update(db: Session, probe: models.Probe, platform: str | None, now: datetime) -> None:
    """Ask the probe to move to the platform's commit. Raises
    :class:`UpdateNotPossible` with the reason when it cannot be asked."""
    if probe.status != "active":
        raise UpdateNotPossible("Only an enrolled probe can be updated")
    if probe.appliance_version:
        raise UpdateNotPossible(
            "This probe is an appliance: it updates itself to the signed image the platform publishes (PROBE_IMAGE)"
        )
    if not platform:
        raise UpdateNotPossible(
            "The platform does not know which commit it runs (deploy it with scripts/deploy.sh, or set PLATFORM_BUILD)"
        )
    if probe.update_status in IN_PROGRESS:
        raise UpdateNotPossible("An update of this probe is already in progress")
    if clean_build(probe.build) and _same(clean_build(probe.build), platform):
        raise UpdateNotPossible(f"The probe already runs the platform's commit {platform[:12]}")
    probe.update_status, probe.update_target = REQUESTED, platform
    probe.update_detail, probe.update_requested_at, probe.update_finished_at = None, now, None
    events.record(db, probe, events.UPDATE_REQUESTED, now, f"to {platform[:12]}")
    db.commit()
    logger.info("Update of probe #%d to %s requested", probe.id, platform[:12])


# ── Probe ───────────────────────────────────────────────────────────────────

def target_for(probe: models.Probe) -> str | None:
    """The commit the probe's updater should move to, while the request
    waits for it."""
    return probe.update_target if probe.update_status == REQUESTED else None


def build_seen(db: Session, probe: models.Probe, build: str | None, now: datetime) -> None:
    """Records the build a probe states; an update whose target it now runs
    is done. The caller commits."""
    build = clean_build(build)
    if not build:
        return
    probe.build = build
    target = clean_build(probe.update_target)
    if probe.update_status in IN_PROGRESS and target and _same(build, target):
        _finish(db, probe, DONE, f"Now runs {build[:12]}", now)


def report(db: Session, probe: models.Probe, status: str, detail: str | None, now: datetime) -> None:
    """What the probe's updater says. Raises :class:`NoUpdatePending` when
    no update is asked, :class:`InvalidUpdateReport` for a bad status."""
    detail = (detail or "").strip()[:MAX_DETAIL] or None
    if probe.update_status not in IN_PROGRESS:
        raise NoUpdatePending(probe.id)
    if status == RUNNING:
        if probe.update_status == REQUESTED:
            probe.update_status = RUNNING
            probe.update_detail = detail
            events.record(db, probe, events.UPDATE_STARTED, now, detail or "")
    elif status in (DONE, FAILED):
        _finish(db, probe, status, detail, now)
    else:
        raise InvalidUpdateReport(f"Unknown update status {status!r}")
    db.commit()


def _finish(db: Session, probe: models.Probe, status: str, detail: str | None, now: datetime) -> None:
    probe.update_status, probe.update_detail, probe.update_finished_at = status, detail, now
    events.record(db, probe, events.UPDATE_DONE if status == DONE else events.UPDATE_FAILED, now, detail or "")
    logger.info("Update of probe #%d %s: %s", probe.id, status, detail or "")


# ── Watchdog ────────────────────────────────────────────────────────────────

def close_stale_updates(db: Session, now: datetime, pickup_after: timedelta, run_after: timedelta) -> int:
    """Fails the updates no updater took (none installed on the VM, or the
    VM is off) and those that never finished."""
    closed = 0
    for probe in db.query(models.Probe).filter(models.Probe.update_status.in_(IN_PROGRESS)).all():
        asked = _utc(probe.update_requested_at) or now
        if probe.update_status == REQUESTED and asked < now - pickup_after:
            detail = ("No updater on the probe's VM took the request. Install it once "
                      "(deploy/probe/README.md, \"Updates from Root\"), or update the probe by hand.")
        elif probe.update_status == RUNNING and asked < now - run_after:
            detail = "The update did not finish. See journalctl -u v0cday-probe-source-update on the probe's VM."
        else:
            continue
        _finish(db, probe, FAILED, detail, now)
        closed += 1
    db.commit()
    return closed
