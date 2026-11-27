"""
What the platform and a probe exchange about a host discovery, as plain
JSON documents. No database here: the probe imports this module.

    platform -> probe   DiscoveryAssignment   the range, the client's allowlist, the time budget
    probe -> platform   progress              {"probed": n, "hosts": [...]}  (answer: stop or not)
    probe -> platform   DiscoveryReport       final status, hosts, addresses probed, error
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

KIND = "discovery"
# One /16 full of hosts at most; a larger list is refused.
MAX_HOSTS = 65_536
MAX_HOSTNAME = 255
MAX_ERROR = 2000
# What a probe may report as the end of a discovery.
DONE, CANCELLED, FAILED = "done", "cancelled", "failed"
FINAL_STATUSES = (DONE, CANCELLED, FAILED)


def parse_hosts(raw: Any, network: ipaddress.IPv4Network) -> list[dict[str, Any]]:
    """Validated hosts, sorted by address: each one an address of
    ``network``, with a reverse DNS name or None. Raises ValueError."""
    if not isinstance(raw, list):
        raise ValueError("hosts must be a list")
    if len(raw) > MAX_HOSTS:
        raise ValueError(f"too many hosts (limit {MAX_HOSTS})")
    hosts: dict[ipaddress.IPv4Address, str | None] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each host is an object")
        try:
            address = ipaddress.IPv4Address(str(item.get("ip", "")))
        except ValueError:
            raise ValueError(f"not an IPv4 address: {item.get('ip')!r}") from None
        if address not in network:
            raise ValueError(f"{address} is outside {network}")
        hostname = item.get("hostname")
        if hostname is not None and not isinstance(hostname, str):
            raise ValueError("hostname must be a string or null")
        hosts[address] = (hostname or None) and hostname[:MAX_HOSTNAME]
    return [{"ip": str(a), "hostname": hosts[a]} for a in sorted(hosts)]


def parse_probed(raw: Any, total: int) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        raise ValueError("probed must be a non-negative integer")
    return min(raw, total)


@dataclass(frozen=True)
class DiscoveryAssignment:
    discovery_id: int
    workspace_id: int
    network_range: str
    allowlist: str | None
    budget_seconds: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": KIND,
            "discovery_id": self.discovery_id,
            "workspace_id": self.workspace_id,
            "network_range": self.network_range,
            "allowlist": self.allowlist,
            "budget_seconds": self.budget_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveryAssignment:
        return cls(
            discovery_id=int(data["discovery_id"]),
            workspace_id=int(data["workspace_id"]),
            network_range=str(data["network_range"]),
            allowlist=data.get("allowlist"),
            budget_seconds=int(data["budget_seconds"]),
        )

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.network_range, strict=False)


@dataclass(frozen=True)
class DiscoveryReport:
    discovery_id: int
    status: str
    probed: int
    hosts: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": KIND,
            "discovery_id": self.discovery_id,
            "status": self.status,
            "probed": self.probed,
            "hosts": list(self.hosts),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveryReport:
        status = data["status"]
        if status not in FINAL_STATUSES:
            raise ValueError(f"unknown final status {status!r}")
        error = data.get("error")
        if error is not None and not isinstance(error, str):
            raise ValueError("error must be a string or null")
        return cls(
            discovery_id=int(data["discovery_id"]),
            status=status,
            probed=int(data["probed"]),
            hosts=list(data.get("hosts") or []),
            error=error[:MAX_ERROR] if error else None,
        )
