"""
The probes of the clients: created by a global admin, enrolled once by the
probe itself, then authenticated on every call.

    create ──token (one use, expires)──► enroll ──secret──► authenticate …
       ▲                                                        │
       └──────── new enrollment (reinstalled VM) ◄── revoke ◄───┘

A new enrollment replaces the probe's secret: the old installation can no
longer sign in. A revoked probe signs in no more and cannot be re-enrolled.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db import models
from app.probes import events, secrets

PENDING, ACTIVE, REVOKED = "pending", "active", "revoked"
ONLINE, OFFLINE = "online", "offline"


class EnrollmentError(Exception):
    """Unknown, used or expired enrollment token."""


class ProbeStateError(Exception):
    """The operation does not apply to the probe in its current state."""


@dataclass(frozen=True)
class Enrollment:
    probe_id: int
    token: str
    expires_at: datetime


def display_status(probe: models.Probe, now: datetime, online_seconds: int) -> str:
    """pending / revoked, or online / offline for an enrolled probe."""
    if probe.status != ACTIVE:
        return probe.status
    seen = _utc(probe.last_seen_at)
    return ONLINE if seen and now - seen <= timedelta(seconds=online_seconds) else OFFLINE


class ProbeRegistry:
    def __init__(self, db: Session, enrollment_ttl: timedelta) -> None:
        self._db = db
        self._ttl = enrollment_ttl

    def create(self, workspace_id: int, name: str, now: datetime) -> Enrollment:
        probe = models.Probe(workspace_id=workspace_id, name=name, status=PENDING, created_at=now)
        self._db.add(probe)
        self._db.flush()
        events.record(self._db, probe, events.CREATED, now, f"name={name}")
        return self._issue_token(probe, now)

    def new_enrollment(self, probe: models.Probe, now: datetime) -> Enrollment:
        if probe.status == REVOKED:
            raise ProbeStateError("A revoked probe cannot be enrolled again: create a new one")
        events.record(self._db, probe, events.TOKEN_RENEWED, now, "the next enrollment replaces the probe's secret")
        return self._issue_token(probe, now)

    def enroll(self, token: str, now: datetime, hostname: str, version: str, ip: str) -> tuple[models.Probe, str]:
        """The probe and its new secret (returned once, stored as a digest)."""
        probe = (
            self._db.query(models.Probe)
            .filter(models.Probe.enrollment_token_hash == secrets.digest(token))
            .first()
        )
        expires = _utc(probe.enrollment_expires_at) if probe else None
        if probe is None or probe.status == REVOKED or expires is None or expires < now:
            raise EnrollmentError("Unknown, used or expired enrollment token")
        secret = secrets.new_secret()
        probe.status = ACTIVE
        probe.secret_hash = secrets.digest(secret)
        probe.enrollment_token_hash = None
        probe.enrollment_expires_at = None
        probe.enrolled_at = now
        self._seen(probe, now, ip, hostname, version)
        events.record(self._db, probe, events.ENROLLED, now, f"host={hostname or '?'} ip={ip} version={version or '?'}")
        self._db.commit()
        return probe, secret

    def authenticate(self, authorization: str | None) -> models.Probe | None:
        parsed = secrets.parse_authorization(authorization)
        if parsed is None:
            return None
        probe = self._db.get(models.Probe, parsed[0])
        if probe is None or probe.status != ACTIVE or not secrets.matches(parsed[1], probe.secret_hash):
            return None
        return probe

    def seen(self, probe: models.Probe, now: datetime, ip: str, hostname: str | None = None, version: str | None = None,
             image: str | None = None, appliance_version: str | None = None) -> None:
        self._seen(probe, now, ip, hostname, version)
        if image and image[:512] != probe.image:
            if probe.image:
                events.record(self._db, probe, events.IMAGE_CHANGED, now, f"{probe.image} -> {image}")
            probe.image = image[:512]
        if appliance_version:
            probe.appliance_version = appliance_version[:64]
        self._db.commit()

    def revoke(self, probe: models.Probe, now: datetime) -> None:
        events.record(self._db, probe, events.REVOKED, now)
        probe.status = REVOKED
        probe.secret_hash = None
        probe.enrollment_token_hash = None
        probe.enrollment_expires_at = None
        self._db.commit()

    def _issue_token(self, probe: models.Probe, now: datetime) -> Enrollment:
        token = secrets.new_secret()
        probe.enrollment_token_hash = secrets.digest(token)
        probe.enrollment_expires_at = now + self._ttl
        self._db.commit()
        return Enrollment(probe.id, token, probe.enrollment_expires_at)

    @staticmethod
    def _seen(probe: models.Probe, now: datetime, ip: str, hostname: str | None, version: str | None) -> None:
        probe.last_seen_at = now
        probe.last_seen_ip = (ip or "")[:64]
        if hostname:
            probe.hostname = hostname[:255]
        if version:
            probe.version = version[:64]


def _utc(moment: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; columns are UTC."""
    if moment is None or moment.tzinfo is not None:
        return moment
    return moment.replace(tzinfo=timezone.utc)
