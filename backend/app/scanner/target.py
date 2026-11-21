"""
Value objects describing *what* is scanned: the scan type and the target.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum


class ScanType(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    API = "api"
    IAC = "iac"
    INVENTORY = "inventory"  # device inventory from a fleet manager (Intune…)

    @classmethod
    def parse(cls, raw: str | None, default: ScanType | None = None) -> ScanType:
        """Parse a stored scan type. Missing values give ``default`` (internal)."""
        if not raw:
            return default or cls.INTERNAL
        return cls(raw.strip().lower())


class InvalidTargetError(ValueError):
    """Raised when a scan target does not contain a usable host."""


_URL_SCHEME = re.compile(r"^https?://", re.IGNORECASE)
UNKNOWN_SCHEME = "unknown"


@dataclass(frozen=True)
class ScanTarget:
    """A parsed scan target: ``raw`` as typed by the user, ``host`` to connect
    to, and ``scheme`` (``http``/``https``, or ``unknown`` for a bare host)."""

    raw: str
    host: str
    scheme: str

    @classmethod
    def parse(cls, raw: str) -> ScanTarget:
        text = (raw or "").strip()
        if _URL_SCHEME.match(text):
            parsed = urllib.parse.urlparse(text)
            host, scheme = parsed.hostname or "", parsed.scheme.lower()
        else:
            host, scheme = _host_of(text), UNKNOWN_SCHEME
        if not host:
            raise InvalidTargetError(f"Target '{raw}' does not contain a host")
        return cls(raw=text, host=host, scheme=scheme)


def _host_of(text: str) -> str:
    """Host part of ``host``, ``host:port``, ``[ipv6]:port`` or ``host/path``."""
    authority = text.split("/", 1)[0]
    if authority.startswith("["):
        return authority[1:].split("]", 1)[0]
    return authority.split(":", 1)[0]
