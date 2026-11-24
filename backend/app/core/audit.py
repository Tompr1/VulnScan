"""
What the audit log records of a mutating request: who (from the session
token, when it is valid), on which client, what, and with what outcome — so
an MSP can tell, per client, who changed what, and spot refused attempts.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.core.auth import verify_jwt

_MAX_ACTION = 255


def audit_entry(method: str, path: str, authorization: str, status_code: int, ip: str, user_agent: str) -> dict[str, Any]:
    """The audit row of a request. An invalid or missing token records no
    actor and no client: only a verified token is trusted."""
    claims = _claims(authorization)
    return {
        "workspace_id": _int_or_none(claims.get("ws")),
        "user_id": _int_or_none(claims.get("uid")),
        "actor_email": str(claims.get("sub") or "")[:255],
        "action": f"{method} {path}"[:_MAX_ACTION],
        "resource": "",
        "status_code": status_code,
        "ip": ip[:64],
        "user_agent": user_agent,
    }


def _claims(authorization: str) -> dict[str, Any]:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return {}
    try:
        return verify_jwt(token.strip())
    except HTTPException:
        return {}


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
