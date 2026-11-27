"""
Allowlist policy — decides whether an internal scan may reach a target.

Each client has its own internal network: the engine asks an
:class:`AllowlistSource` for the policy of the client being scanned.
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable
from typing import Protocol

from app.scanner.target import ScanTarget, ScanType

logger = logging.getLogger(__name__)

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class AllowlistSource(Protocol):
    def policy_for(self, workspace_id: int) -> AllowlistPolicy:
        """The policy that applies to the scans of this client."""


class AllowlistPolicy:
    """Internal network boundary made of CIDRs, single IPs and domains.

    - ``.example.com`` allows ``example.com`` and all of its sub-domains;
    - ``example.com`` allows that exact host only;
    - an empty allowlist (or ``*``) allows everything.

    External scans target public assets and are never restricted.
    """

    def __init__(self, entries: Iterable[str]) -> None:
        self._networks: list[_IpNetwork] = []
        self._domains: set[str] = set()
        self._domain_suffixes: set[str] = set()
        self._entries = [e.strip().lower() for e in entries if e.strip()]
        self._allow_all = not self._entries
        for entry in self._entries:
            self._add(entry)

    @classmethod
    def from_setting(cls, raw: str | None) -> AllowlistPolicy:
        """Build from the comma-separated ``ALLOWLIST`` setting."""
        text = (raw or "").strip()
        return cls([] if text == "*" else text.split(","))

    def policy_for(self, workspace_id: int) -> AllowlistPolicy:
        """The same policy for every client (a source of one policy)."""
        return self

    def allows(self, target: ScanTarget, scan_type: ScanType) -> bool:
        if scan_type is ScanType.EXTERNAL or self._allow_all:
            return True
        try:
            address = ipaddress.ip_address(target.host)
        except ValueError:
            return self._allows_domain(target.host)
        return any(address in network for network in self._networks)

    def allows_network(self, network: _IpNetwork) -> bool:
        """Whether every address of ``network`` is allowed (a range to
        discover must lie inside one allowed network)."""
        if self._allow_all:
            return True
        return any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in self._networks
        )

    def _allows_domain(self, host: str) -> bool:
        name = host.lower().rstrip(".")
        if name in self._domains:
            return True
        return any(name == suffix or name.endswith("." + suffix) for suffix in self._domain_suffixes)

    def __str__(self) -> str:
        return ",".join(self._entries) or "*"

    def _add(self, entry: str) -> None:
        if entry.startswith("."):
            self._domain_suffixes.add(entry.lstrip("."))
            return
        try:
            self._networks.append(ipaddress.ip_network(entry, strict=False))
            return
        except ValueError:
            pass
        if "/" in entry:
            logger.warning("Ignoring invalid allowlist CIDR: %s", entry)
            return
        self._domains.add(entry)
