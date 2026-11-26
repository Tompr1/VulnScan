"""
PlatformClient — the probe's side of the platform API (``/probe/v1``).

Errors are sorted by what the agent should do about them:
- :class:`ProbeRejected` (401): the probe was revoked or re-enrolled
  elsewhere — stop, a human must act;
- :class:`JobGone` (404): the job is no longer this probe's (cancelled,
  failed by the watchdog) — drop it;
- :class:`MessageRefused` (422): the platform refuses what was sent — drop
  it, retrying would not change the answer;
- :class:`PlatformUnavailable`: network error, 5xx, 503 — try again later.
"""
from __future__ import annotations

import json
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

import httpx

from app.scan_jobs.assignment import ScanAssignment, ScanReport

API = "/probe/v1"
VERSION_HEADER = "X-Probe-Version"
# Above the longest wait the platform allows on /jobs/next (30 s).
_LONG_POLL_MARGIN = 15.0
_PRODUCTS_PER_LOOKUP = 5000


class PlatformError(Exception):
    pass


class ProbeRejected(PlatformError):
    pass


class JobGone(PlatformError):
    pass


class MessageRefused(PlatformError):
    pass


class PlatformUnavailable(PlatformError):
    pass


@dataclass(frozen=True)
class Enrolled:
    probe_id: int
    workspace_id: int
    name: str
    credential: str


@dataclass(frozen=True)
class Dataset:
    etag: str
    content: list[Any]


def open_http(base_url: str, ca_bundle: str | None = None, client_cert: str | None = None,
              client_key: str | None = None, timeout: float = 30.0) -> httpx.Client:
    """The HTTP client of a probe: TLS checked against ``ca_bundle`` (or the
    system's), with a client certificate when one is configured."""
    cert = (client_cert, client_key) if client_cert and client_key else client_cert
    return httpx.Client(base_url=base_url.rstrip("/"), verify=ca_bundle or True, cert=cert, timeout=timeout)


class PlatformClient:
    def __init__(self, http: httpx.Client, authorization: str | None, version: str) -> None:
        self._http = http
        self._authorization = authorization
        self._version = version

    # ── Identity ─────────────────────────────────────────────────────────

    def enroll(self, token: str, hostname: str) -> Enrolled:
        data = self._call("POST", "/enroll", json={"token": token, "hostname": hostname[:255], "version": self._version},
                          authenticated=False)
        return Enrolled(int(data["probe_id"]), int(data["workspace_id"]), str(data.get("name") or ""), str(data["credential"]))

    def heartbeat(self, hostname: str | None = None) -> dict[str, Any]:
        return self._call("POST", "/heartbeat", json={"hostname": hostname, "version": self._version})

    # ── Jobs ─────────────────────────────────────────────────────────────

    def next_job(self, wait: int = 25) -> ScanAssignment | None:
        response = self._send("GET", "/jobs/next", params={"wait": wait}, timeout=wait + _LONG_POLL_MARGIN)
        if response.status_code == 204:
            return None
        return ScanAssignment.from_dict(self._json(response))

    def progress(self, job_id: int, document: dict[str, Any]) -> bool:
        """Sends the scan progress; True when the platform says to stop."""
        return bool(self._call("POST", f"/jobs/{job_id}/progress", json=document).get("cancel"))

    def report(self, job_id: int, report: ScanReport) -> None:
        self._call("POST", f"/jobs/{job_id}/report", json=report.to_dict())

    # ── Reference data ───────────────────────────────────────────────────

    def reference_status(self) -> dict[str, Any]:
        return self._call("GET", "/reference/status")

    def dataset(self, kind: str, etag: str | None = None) -> Dataset | None:
        """The dataset, or None when ``etag`` is still current."""
        headers = {"If-None-Match": f'"{etag}"'} if etag else {}
        response = self._send("GET", f"/reference/datasets/{kind}", headers=headers)
        if response.status_code == 304:
            return None
        return Dataset(response.headers.get("ETag", "").strip('"'), self._json(response))

    def cve_records(self, products: Collection[tuple[str, str]]) -> list[dict[str, Any]]:
        pairs = sorted({(v, p) for v, p in products})
        records: list[dict[str, Any]] = []
        for start in range(0, len(pairs), _PRODUCTS_PER_LOOKUP):
            chunk = [list(pair) for pair in pairs[start:start + _PRODUCTS_PER_LOOKUP]]
            records += self._call("POST", "/reference/cve-records", json={"products": chunk}).get("records", [])
        return records

    # ── Transport ────────────────────────────────────────────────────────

    def _call(self, method: str, path: str, authenticated: bool = True, **kwargs: Any) -> Any:
        return self._json(self._send(method, path, authenticated=authenticated, **kwargs))

    def _send(self, method: str, path: str, authenticated: bool = True, headers: dict[str, str] | None = None,
              **kwargs: Any) -> httpx.Response:
        all_headers = {VERSION_HEADER: self._version, **(headers or {})}
        if authenticated and self._authorization:
            all_headers["Authorization"] = self._authorization
        try:
            response = self._http.request(method, API + path, headers=all_headers, **kwargs)
        except httpx.HTTPError as exc:
            raise PlatformUnavailable(f"{method} {path}: {exc}") from exc
        status = response.status_code
        if status in (200, 201, 202, 204, 304):
            return response
        detail = _detail(response)
        if status == 401:
            raise ProbeRejected(detail)
        if status == 403:
            # Refused channel (HTTP instead of HTTPS): configuration, not transient.
            raise ProbeRejected(detail)
        if status == 404:
            raise JobGone(detail)
        if status in (400, 409, 413, 422):
            raise MessageRefused(detail)
        raise PlatformUnavailable(f"{method} {path}: HTTP {status} {detail}")

    @staticmethod
    def _json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise PlatformUnavailable(f"Unreadable answer from the platform: {exc}") from exc


def _detail(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        detail = None
    return str(detail or response.text[:200] or response.reason_phrase)
