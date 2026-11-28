"""
What every audit rule shares: the issue it reports, the policy it applies
and the context it reads (reference data resolved once per audit).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Protocol

from app.cve.kev import KevCatalog
from app.cve.matcher import CveCatalog
from app.inventory.audit.cves import VulnerabilityIndex
from app.inventory.audit.fleet import FleetBaseline
from app.inventory.audit.lifecycle import CatalogUnavailableError, SupportCatalog, SupportCycle
from app.inventory.audit.products import InstalledRelease
from app.inventory.domain import Device


@dataclass(frozen=True)
class AuditIssue:
    """One problem on one device. ``subject`` identifies it across audits
    (with the rule and the device), so it deliberately leaves out versions:
    Chrome going from one outdated version to another is the same issue."""

    rule: str
    subject: str
    title: str
    severity: str
    description: str
    remediation: str
    evidence: tuple[tuple[str, str], ...] = ()
    confidence: float = 1.0
    references: tuple[str, ...] = ()
    cve: str | None = None  # the most urgent CVE, when the issue is about CVEs
    cves: tuple[str, ...] = ()  # all of them (the description lists the first ones)
    cvss: float | None = None
    is_kev: bool = False


@dataclass(frozen=True)
class AuditPolicy:
    support_warning_days: int = 60  # warn before an OS loses support
    app_support_grace_days: int = 14  # Chrome / Firefox majors expire every few weeks
    android_patch_max_age_days: int = 90
    fleet_min_devices: int = 2

    def __post_init__(self) -> None:
        if min(self.support_warning_days, self.app_support_grace_days, self.android_patch_max_age_days) < 0:
            raise ValueError("audit policy durations cannot be negative")
        if self.fleet_min_devices < 1:
            raise ValueError("fleet_min_devices must be at least 1")


class LifecycleLookup:
    """Vendor lifecycle of a release, remembering which products could not be
    checked (endoflife.date unreachable) so the audit can say so."""

    def __init__(self, catalog: SupportCatalog) -> None:
        self._catalog = catalog
        self.unavailable: set[str] = set()

    def cycle_of(self, release: InstalledRelease) -> SupportCycle | None:
        try:
            cycles = self._catalog.cycles(release.product.slug)
        except CatalogUnavailableError:
            self.unavailable.add(release.product.slug)
            return None
        return release.cycle_in(cycles)


@dataclass
class AuditContext:
    today: date
    lifecycle: LifecycleLookup
    fleet: FleetBaseline
    policy: AuditPolicy = field(default_factory=AuditPolicy)
    vulnerabilities: VulnerabilityIndex = field(default_factory=VulnerabilityIndex.empty)


class DeviceRule(Protocol):
    def evaluate(self, device: Device, context: AuditContext) -> Iterable[AuditIssue]: ...


@dataclass(frozen=True)
class ReferenceData:
    """What devices are compared with, for one workspace: support lifecycle,
    CVE catalog and CISA KEV. ``notes`` are known gaps (KEV dataset missing,
    NVD history import still running…) reported with the audit."""

    lifecycle: SupportCatalog
    cves: CveCatalog
    kev: KevCatalog
    notes: tuple[str, ...] = ()
