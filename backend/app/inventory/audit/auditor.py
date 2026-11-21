"""
DeviceAuditor — runs every rule on every device of a fleet.

The fleet baseline is computed once from all the devices, then each rule
sees one device at a time. A rule failing on one odd device is logged and
counted: it must not cost the audit of the 299 others.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from app.inventory.audit.fleet import FleetBaseline
from app.inventory.audit.lifecycle import SupportCatalog
from app.inventory.audit.rules import AuditContext, AuditIssue, AuditPolicy, DeviceRule, LifecycleLookup
from app.inventory.domain import Device

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditOutcome:
    issues: dict[str, list[AuditIssue]] = field(default_factory=dict)  # by device external id
    unavailable_products: frozenset[str] = frozenset()  # lifecycle not checked
    rule_errors: int = 0

    @property
    def issue_count(self) -> int:
        return sum(map(len, self.issues.values()))

    @property
    def complete(self) -> bool:
        return not self.unavailable_products and not self.rule_errors


class DeviceAuditor:
    def __init__(
        self,
        rules: Sequence[DeviceRule],
        catalog_factory: Callable[[], SupportCatalog],
        policy: AuditPolicy | None = None,
        today: Callable[[], date] = lambda: datetime.now(timezone.utc).date(),
    ) -> None:
        self._rules = list(rules)
        self._catalog_factory = catalog_factory
        self._policy = policy or AuditPolicy()
        self._today = today

    def audit(self, devices: Sequence[Device]) -> AuditOutcome:
        # A fresh catalog per audit: lifecycle data is re-read every run.
        lifecycle = LifecycleLookup(self._catalog_factory())
        context = AuditContext(
            today=self._today(),
            lifecycle=lifecycle,
            fleet=FleetBaseline.of(devices, self._policy.fleet_min_devices),
            policy=self._policy,
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
        return AuditOutcome(issues, frozenset(lifecycle.unavailable), errors)
