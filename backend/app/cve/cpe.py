"""
CPE value objects — the vocabulary shared by every CVE matcher.

A CPE 2.3 name (``cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*``) identifies a
product; NVD attaches to each CVE the CPEs it affects, optionally bounded by a
version range. Matching an installed product against a CVE therefore means:
same product (vendor + product name, modulo known vendor renames) and an
installed version inside the range.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.cve.version_cmp import parse

# NVD files some products under more than one vendor name after acquisitions.
# Each alias maps to ONE canonical name so both sides normalise identically.
VENDOR_ALIASES: dict[str, str] = {
    "f5": "nginx",  # F5 acquired nginx; NVD uses both
    "pivotal_software": "vmware",  # Spring: Pivotal then VMware
    "pivotal": "vmware",
    "sun": "oracle",  # older Java CVEs are filed under Sun
}

ANY = "*"

ProductKey = tuple[str, str]
"""(canonical vendor, product) — what two CPEs must share to be comparable."""


def canonical_vendor(vendor: str) -> str:
    vendor = vendor.lower()
    return VENDOR_ALIASES.get(vendor, vendor)


@dataclass(frozen=True)
class Cpe:
    part: str  # a = application, o = operating system, h = hardware
    vendor: str
    product: str
    version: str = ANY

    @classmethod
    def parse(cls, cpe23: str | None) -> Cpe | None:
        """Parse a ``cpe:2.3:…`` name; None when it is not one."""
        fields = (cpe23 or "").split(":")
        if len(fields) < 6 or fields[0] != "cpe" or not fields[3] or not fields[4]:
            return None
        return cls(part=fields[2], vendor=fields[3].lower(), product=fields[4].lower(), version=fields[5] or ANY)

    def to_cpe23(self) -> str:
        """The ``cpe:2.3:…`` name of the fields kept here (the others are ANY)."""
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:*:*:*:*:*:*:*"

    @property
    def product_key(self) -> ProductKey:
        # The part is deliberately ignored: NVD sometimes files the same
        # product as an application and as an OS component (e.g. linux_kernel).
        return canonical_vendor(self.vendor), self.product

    def same_product(self, other: Cpe) -> bool:
        return self.product_key == other.product_key

    def __str__(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:*:*:*:*:*:*:*"


@dataclass(frozen=True)
class VersionRange:
    """Vulnerable versions of a CPE match; all bounds optional."""

    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    @classmethod
    def from_nvd(cls, match: Mapping[str, Any]) -> VersionRange:
        return cls(
            start_including=match.get("versionStartIncluding") or None,
            start_excluding=match.get("versionStartExcluding") or None,
            end_including=match.get("versionEndIncluding") or None,
            end_excluding=match.get("versionEndExcluding") or None,
        )

    @property
    def is_unbounded(self) -> bool:
        return not (self.start_including or self.start_excluding or self.end_including or self.end_excluding)

    def contains(self, installed: str | None) -> bool:
        """True when ``installed`` is vulnerable.

        An unbounded range affects every version. With bounds, an unknown or
        unparsable installed version is treated as not vulnerable: claiming a
        CVE we cannot place would only produce noise.
        """
        if self.is_unbounded:
            return True
        version = parse(installed) if installed else None
        if version is None:
            return False
        return all(check(version) for check in self._checks())

    def _checks(self):
        bounds = (
            (self.start_including, lambda v, b: v >= b),
            (self.start_excluding, lambda v, b: v > b),
            (self.end_including, lambda v, b: v <= b),
            (self.end_excluding, lambda v, b: v < b),
        )
        for raw_bound, holds in bounds:
            bound = parse(raw_bound) if raw_bound else None
            if bound is not None:
                yield lambda v, bound=bound, holds=holds: holds(v, bound)

    def describe(self) -> str:
        parts = []
        if self.start_including:
            parts.append(f">= {self.start_including}")
        if self.start_excluding:
            parts.append(f"> {self.start_excluding}")
        if self.end_including:
            parts.append(f"<= {self.end_including}")
        if self.end_excluding:
            parts.append(f"< {self.end_excluding}")
        return " and ".join(parts) if parts else "all versions"


@dataclass(frozen=True)
class CpeMatch:
    """One vulnerable configuration of a CVE: a CPE and its version range."""

    cpe: Cpe
    versions: VersionRange

    @classmethod
    def from_nvd(cls, match: Mapping[str, Any]) -> CpeMatch | None:
        cpe = Cpe.parse(match.get("cpe23") or match.get("criteria"))
        return cls(cpe, VersionRange.from_nvd(match)) if cpe else None

    def to_nvd(self) -> dict[str, str]:
        """The NVD form :meth:`from_nvd` reads back."""
        bounds = {
            "versionStartIncluding": self.versions.start_including,
            "versionStartExcluding": self.versions.start_excluding,
            "versionEndIncluding": self.versions.end_including,
            "versionEndExcluding": self.versions.end_excluding,
        }
        return {"cpe23": self.cpe.to_cpe23(), **{k: v for k, v in bounds.items() if v}}

    def affects(self, candidate: Cpe, installed_version: str | None) -> bool:
        """Does this configuration cover ``candidate`` at ``installed_version``?

        When the match pins an exact version (no range), the candidate must be
        that version.
        """
        if not self.cpe.same_product(candidate):
            return False
        if self.versions.is_unbounded and self.cpe.version not in (ANY, "-"):
            return _same_version(installed_version, self.cpe.version)
        return self.versions.contains(installed_version)


def _same_version(installed: str | None, pinned: str) -> bool:
    """Version equality; versions packaging cannot parse (OpenSSH "8.9p1")
    are compared as case-insensitive text."""
    if not installed:
        return False
    parsed_installed, parsed_pinned = parse(installed), parse(pinned)
    if parsed_installed is not None and parsed_pinned is not None:
        return parsed_installed == parsed_pinned
    return installed.strip().lower() == pinned.strip().lower()
