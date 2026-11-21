"""
DeviceAuditor — runs every rule on every device of a fleet.

Reference data is resolved once per audit: the fleet baseline from all the
devices, the CVEs of every product found in the fleet (one catalog query),
the support lifecycle as rules ask for it. Then each rule sees one device at
a time. A rule failing on one odd device is logged and counted: it must not
cost the audit of the 299 others.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from app.inventory.audit.base import AuditContext, AuditIssue, AuditPolicy, DeviceRule, LifecycleLookup, ReferenceData
from app.inventory.audit.cves import VulnerabilityIndex
from app.inventory.audit.fleet import FleetBaseline
from app.inventory.domain import Device

logger = logging.getLogger(__name__)

CVE_CATALOG_FAILED = "The CVE catalog could not be read: known vulnerabilities were not checked."


@dataclass(frozen=True)
class AuditOutcome:
    issues: dict[str, list[AuditIssue]] = field(default_factory=dict)  # by device external id
    unavailable_products: frozenset[str] = frozenset()  # lifecycle not checked
    rule_errors: int = 0
    notes: tuple[str, ...] = ()  # other known gaps (reference data missing…)

    @property
    def issue_count(self) -> int:
        return sum(map(len, self.issues.values()))

    @property
    def complete(self) -> bool:
        return not self.unavailable_products and not self.rule_errors and not self.notes


class DeviceAuditor:
    def __init__(
        self,
        rules: Sequence[DeviceRule],
        policy: AuditPolicy | None = None,
        today: Callable[[], date] = lambda: datetime.now(timezone.utc).date(),
    ) -> None:
        self._rules = list(rules)
        self._policy = policy or AuditPolicy()
        self._today = today

    def audit(self, devices: Sequence[Device], reference: ReferenceData) -> AuditOutcome:
        notes = list(reference.notes)
        vulnerabilities = self._vulnerabilities(devices, reference, notes)
        lifecycle = LifecycleLookup(reference.lifecycle)
        context = AuditContext(
            today=self._today(),
            lifecycle=lifecycle,
            fleet=FleetBaseline.of(devices, self._policy.fleet_min_devices),
            policy=self._policy,
            vulnerabilities=vulnerabilities,
        )
        issues: dict[str, list[AuditIssue]] = {}
        errors = 0
        for device in devices:
            found = []
            for rule in self._rules:
                try:
                    found += rule.evaluate(device, context)
                except Exception:  # one odd record must not stop the fleet audit
                    errors += 1
                    logger.exception("Audit rule %s failed on device %s", type(rule).__name__, device.external_id)
            if found:
                issues[device.external_id] = found
        return AuditOutcome(issues, frozenset(lifecycle.unavailable), errors, tuple(notes))

    @staticmethod
    def _vulnerabilities(devices: Sequence[Device], reference: ReferenceData, notes: list[str]) -> VulnerabilityIndex:
        try:
            return VulnerabilityIndex.build(devices, reference.cves, reference.kev)
        except Exception:  # database down…: the lifecycle audit still runs
            logger.exception("CVE catalog lookup failed during the inventory audit")
            notes.append(CVE_CATALOG_FAILED)
            return VulnerabilityIndex.empty()
