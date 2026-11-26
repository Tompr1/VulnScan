"""
API of the scan probes (``/probe/v1``): the only calls a probe makes, always
from the client's network out to the platform.

A probe signs in with ``Authorization: Probe <id>.<secret>`` (from its
enrollment) and is bound to one client. Assignments carry credentials in
clear, so the whole API is refused over plain HTTP unless
PROBE_REQUIRE_HTTPS is turned off (lab without TLS).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.job_queue import QueueUnavailableError, get_job_queue
from app.core.net import client_ip, is_https
from app.db.session import SessionLocal
from app.probes.gateway import InvalidMessage, ProbeGateway, ProbeIdentity, UnknownDataset, UnknownJob
from app.probes import secrets
from app.probes.registry import EnrollmentError
from app.scan_jobs.assigner import JobAssigner
from app.scan_jobs.repository import SqlScanJobRepository
from app.scanner.cancellation import RedisCancellationSignal
from app.scanner.client_allowlists import SqlClientAllowlists
from app.scanner.sql_resources import SqlCredentialVault

logger = logging.getLogger(__name__)

VERSION_HEADER = "X-Probe-Version"
MAX_WAIT_SECONDS = 30
_POLL_INTERVAL_SECONDS = 2.0
# Assignments hold credentials: no cache may keep a copy.
_NO_STORE = {"Cache-Control": "no-store"}


def get_probe_gateway() -> ProbeGateway:
    return ProbeGateway(
        session_factory=SessionLocal,
        assigner=JobAssigner(
            SqlScanJobRepository(SessionLocal),
            lambda workspace_id: SqlCredentialVault(SessionLocal, workspace_id),
            SqlClientAllowlists(SessionLocal, platform_default=settings.ALLOWLIST),
        ),
        reports=get_job_queue(),
        cancellation=RedisCancellationSignal.from_url(settings.REDIS_URL),
        clock=lambda: datetime.now(timezone.utc),
        enrollment_ttl=timedelta(hours=settings.PROBE_ENROLLMENT_TTL_HOURS),
    )


def require_secure_channel(request: Request) -> None:
    if settings.PROBE_REQUIRE_HTTPS and not is_https(request):
        raise HTTPException(403, "The probe API is only served over HTTPS")


router = APIRouter(prefix="/probe/v1", tags=["probe-agent"], dependencies=[Depends(require_secure_channel)])


def require_probe(request: Request, gateway: ProbeGateway = Depends(get_probe_gateway)) -> ProbeIdentity:
    probe = gateway.authenticate(
        request.headers.get("Authorization"), client_ip(request), request.headers.get(VERSION_HEADER),
    )
    if probe is None:
        raise HTTPException(401, "Unknown or revoked probe", headers={"WWW-Authenticate": "Probe"})
    return probe


class EnrollBody(BaseModel):
    token: str = Field(min_length=16, max_length=256)
    hostname: str = Field(default="", max_length=255)
    version: str = Field(default="", max_length=64)


class HeartbeatBody(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=64)


class CveLookupBody(BaseModel):
    products: list[Any]


@router.post("/enroll", status_code=201)
def enroll(body: EnrollBody, request: Request, gateway: ProbeGateway = Depends(get_probe_gateway)):
    """Trades the one-time enrollment token for the probe's credential,
    returned once: the probe keeps it in its configuration."""
    try:
        probe, secret = gateway.enroll(body.token, body.hostname, body.version, client_ip(request))
    except EnrollmentError:
        raise HTTPException(401, "Unknown, used or expired enrollment token") from None
    return Response(
        content=_json({"probe_id": probe.id, "workspace_id": probe.workspace_id, "name": probe.name,
                       "credential": secrets.credential(probe.id, secret)}),
        status_code=201, media_type="application/json", headers=_NO_STORE,
    )


@router.post("/heartbeat")
def heartbeat(
    body: HeartbeatBody,
    request: Request,
    probe: ProbeIdentity = Depends(require_probe),
    gateway: ProbeGateway = Depends(get_probe_gateway),
):
    gateway.heartbeat(probe, client_ip(request), body.hostname, body.version)
    return {"probe_id": probe.id, "workspace_id": probe.workspace_id,
            "server_time": datetime.now(timezone.utc).isoformat()}


@router.get("/jobs/next")
async def next_job(
    wait: int = Query(default=25, ge=0, le=MAX_WAIT_SECONDS),
    probe: ProbeIdentity = Depends(require_probe),
    gateway: ProbeGateway = Depends(get_probe_gateway),
):
    """The next job of the probe's client, waiting up to ``wait`` seconds
    for one (long polling); 204 when there is none."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait
    while True:
        assignment = await run_in_threadpool(gateway.next_assignment, probe)
        if assignment is not None:
            return Response(content=_json(assignment.to_dict()), media_type="application/json", headers=_NO_STORE)
        remaining = deadline - loop.time()
        if remaining <= 0:
            return Response(status_code=204)
        await asyncio.sleep(min(_POLL_INTERVAL_SECONDS, remaining))


@router.post("/jobs/{job_id}/progress")
def job_progress(
    job_id: int,
    document: dict[str, Any],
    probe: ProbeIdentity = Depends(require_probe),
    gateway: ProbeGateway = Depends(get_probe_gateway),
):
    """Stores the scan progress; ``cancel`` tells the probe to stop."""
    try:
        return {"cancel": gateway.progress(probe, job_id, document)}
    except InvalidMessage as exc:
        raise HTTPException(422, str(exc)) from None
    except UnknownJob:
        raise HTTPException(404, "Job not found") from None


@router.post("/jobs/{job_id}/report", status_code=202)
def job_report(
    job_id: int,
    report: dict[str, Any],
    probe: ProbeIdentity = Depends(require_probe),
    gateway: ProbeGateway = Depends(get_probe_gateway),
):
    """Queues the job's report (findings or failure) for finalization. A
    report sent twice is finalized once."""
    try:
        gateway.report(probe, job_id, report)
    except InvalidMessage as exc:
        raise HTTPException(422, str(exc)) from None
    except UnknownJob:
        raise HTTPException(404, "Job not found") from None
    except QueueUnavailableError:
        raise HTTPException(503, "The platform cannot accept the report now: send it again later") from None
    return {"accepted": True}


@router.get("/reference/status")
def reference_status(_probe: ProbeIdentity = Depends(require_probe), gateway: ProbeGateway = Depends(get_probe_gateway)):
    """Version (ETag) of each dataset, and whether the CVE catalog in the
    platform's database is complete (otherwise the probe completes it with
    the nvd_cpe_cve dataset, as the platform does)."""
    return gateway.reference_status()


@router.get("/reference/datasets/{kind}")
def reference_dataset(
    kind: str,
    request: Request,
    _probe: ProbeIdentity = Depends(require_probe),
    gateway: ProbeGateway = Depends(get_probe_gateway),
):
    try:
        dataset = gateway.dataset(kind)
    except UnknownDataset:
        raise HTTPException(404, "Unknown dataset") from None
    etag = f'"{dataset.etag}"'
    if request.headers.get("If-None-Match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(content=_json(dataset.content), media_type="application/json", headers={"ETag": etag})


@router.post("/reference/cve-records")
def reference_cve_records(
    body: CveLookupBody,
    _probe: ProbeIdentity = Depends(require_probe),
    gateway: ProbeGateway = Depends(get_probe_gateway),
):
    try:
        return {"records": gateway.cve_records(body.products)}
    except InvalidMessage as exc:
        raise HTTPException(422, str(exc)) from None


def _json(value: Any) -> str:
    return json.dumps(value)
