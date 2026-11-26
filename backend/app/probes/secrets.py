"""
Enrollment tokens and probe secrets.

Both are 256-bit random values: a SHA-256 digest is enough to store them (no
password hashing needed against guessing), and digests are compared in
constant time.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

# Authorization header of a probe: "Probe <id>.<secret>".
SCHEME = "Probe"


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def matches(value: str, stored_digest: str | None) -> bool:
    return bool(stored_digest) and hmac.compare_digest(digest(value), stored_digest)


def credential(probe_id: int, secret: str) -> str:
    """What the probe sends after the scheme, and keeps in its configuration."""
    return f"{probe_id}.{secret}"


def parse_authorization(header: str | None) -> tuple[int, str] | None:
    """(probe id, secret) from an Authorization header, or None."""
    scheme, _, value = (header or "").partition(" ")
    if scheme != SCHEME:
        return None
    probe_id, dot, secret = value.strip().partition(".")
    if not dot or not secret or not probe_id.isdigit():
        return None
    return int(probe_id), secret
