"""
Minimal Microsoft Graph client (application permissions, read-only).

- Authentication: OAuth 2.0 client-credentials flow against Entra ID; the
  token is cached until shortly before it expires.
- Paging: follows ``@odata.nextLink``.
- Throttling: 429 / 503 / 504 are retried after ``Retry-After`` seconds
  (Intune throttles per tenant), with an exponential fallback.
- Errors are turned into explicit exceptions whose message says what to fix
  (wrong secret, missing admin consent…), since they are shown to the user.

The HTTP layer is an injected ``httpx.Client``: tests plug a MockTransport.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

GRAPH_URL = "https://graph.microsoft.com/v1.0"
LOGIN_URL = "https://login.microsoftonline.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
REQUIRED_PERMISSION = "DeviceManagementManagedDevices.Read.All"

_RETRYABLE = {429, 503, 504}
_TOKEN_REFRESH_MARGIN_SECONDS = 120


class GraphError(RuntimeError):
    """Graph answered with an error that retrying will not fix."""


class GraphAuthError(GraphError):
    """Entra ID refused the application credentials."""


class GraphPermissionError(GraphError):
    """The application is authenticated but lacks a Graph permission."""


@dataclass(frozen=True)
class EntraAppCredentials:
    tenant_id: str
    client_id: str
    client_secret: str = field(repr=False)


class GraphClient:
    def __init__(
        self,
        credentials: EntraAppCredentials,
        http: httpx.Client | None = None,
        max_retries: int = 4,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._credentials = credentials
        self._http = http or httpx.Client(timeout=60)
        self._max_retries = max_retries
        self._monotonic = monotonic
        self._sleep = sleep
        self._token: str | None = None
        self._token_expires_at = 0.0

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        url = path if path.startswith("https://") else f"{GRAPH_URL}{path}"
        return self._request(url, params)

    def get_all(self, path: str, params: Mapping[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """Every item of a collection, across pages."""
        page = self.get(path, params)
        while True:
            yield from page.get("value") or []
            next_link = page.get("@odata.nextLink")
            if not next_link:
                return
            page = self.get(next_link)  # the link already carries the query

    def _request(self, url: str, params: Mapping[str, Any] | None) -> dict[str, Any]:
        token_refreshed = False
        for attempt in range(self._max_retries + 1):
            response = self._http.get(url, params=params, headers={"Authorization": f"Bearer {self._access_token()}"})
            if response.status_code == 401 and not token_refreshed:
                self._token = None  # expired or revoked: get a new one, once
                token_refreshed = True
                continue
            if response.status_code in _RETRYABLE:
                if attempt == self._max_retries:
                    break
                self._sleep(_retry_delay(response, attempt))
                continue
            return _json_or_raise(response)
        raise GraphError(f"Microsoft Graph is still throttling after {self._max_retries} retries: {url}")

    def _access_token(self) -> str:
        if self._token and self._monotonic() < self._token_expires_at:
            return self._token
        credentials = self._credentials
        response = self._http.post(
            f"{LOGIN_URL}/{credentials.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scope": GRAPH_SCOPE,
            },
        )
        body = _json_body(response)
        if response.status_code != 200 or "access_token" not in body:
            raise GraphAuthError(_auth_error_message(body))
        self._token = body["access_token"]
        self._token_expires_at = self._monotonic() + float(body.get("expires_in", 3600)) - _TOKEN_REFRESH_MARGIN_SECONDS
        return self._token


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    try:
        return max(0.0, float(response.headers.get("Retry-After", "")))
    except ValueError:
        return float(2**attempt)


def _json_body(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _json_or_raise(response: httpx.Response) -> dict[str, Any]:
    if response.status_code == 200:
        return _json_body(response)
    error = _json_body(response).get("error") or {}
    detail = error.get("message") if isinstance(error, dict) else str(error)
    if response.status_code == 403:
        raise GraphPermissionError(
            f"Access denied by Microsoft Graph. Grant the application permission "
            f"{REQUIRED_PERMISSION} and an admin consent in Entra ID. ({detail or 'Forbidden'})"
        )
    raise GraphError(f"Microsoft Graph error {response.status_code}: {detail or response.reason_phrase}")


# Entra ID error codes worth translating for the user.
_AUTH_HINTS = {
    "AADSTS7000215": "the client secret is wrong",
    "AADSTS7000222": "the client secret has expired",
    "AADSTS700016": "no application with this client ID exists in the tenant",
    "AADSTS90002": "the tenant ID does not exist",
    "AADSTS900023": "the tenant ID is not valid",
}


def _auth_error_message(body: Mapping[str, Any]) -> str:
    description = str(body.get("error_description") or body.get("error") or "unknown error")
    hint = next((text for code, text in _AUTH_HINTS.items() if code in description), None)
    first_line = description.splitlines()[0]
    return f"Entra ID refused the credentials: {hint}. ({first_line})" if hint else f"Entra ID refused the credentials. ({first_line})"
