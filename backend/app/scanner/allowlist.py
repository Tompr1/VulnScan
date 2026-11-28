"""
Allowlist policy — decides whether an internal scan may reach a target.

Each client has its own internal network: the engine asks an
:class:`AllowlistSource` for the policy of the client being scanned.
"""
from __future__ import annotations

import ipaddress
import re
import logging
from collections.abc import Iterable
from typing import Protocol

from app.scanner.target import ScanTarget, ScanType

logger = logging.getLogger(__name__)

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


_DOMAIN = re.compile(r"^\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


def parse_entries(raw: str | None) -> list[str]:
    """The entries of an allowlist typed by an admin (comma or space
    separated): CIDR ranges, IPs, host names, ``.domain`` suffixes, or ``*``
    alone. Raises ValueError naming the first unusable entry."""
    entries = [e.strip().lower() for e in re.split(r"[,\s]+", raw or "") if e.strip()]
    for entry in entries:
        if entry == "*":
            if len(entries) > 1:
                raise ValueError("'*' allows every target: use it alone")
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
            continue
        except ValueError:
            pass
        if "/" in entry or not _DOMAIN.match(entry):
            raise ValueError(f"Invalid entry '{entry}': use a CIDR range (192.168.3.0/24), an IP, or a domain (.corp.local)")
    return entries


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

    def allows_target(self, raw: str, scan_type: ScanType) -> bool:
        """Whether a target as typed by the user may be scanned: a CIDR range
        must lie entirely inside an allowed network (its first address is not
        enough), and every entry of a comma-separated list must be allowed.

        Raises :class:`app.scanner.target.InvalidTargetError` for an entry
        without a host."""
        if scan_type is ScanType.EXTERNAL or self._allow_all:
            return True
        entries = [entry.strip() for entry in (raw or "").split(",") if entry.strip()]
        if not entries:
            entries = [raw]
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                if not self.allows(ScanTarget.parse(entry), scan_type):
                    return False
                continue
            if not self.allows_network(network):
                return False
        return True

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
