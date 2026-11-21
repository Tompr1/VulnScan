"""
Inventory audit use case: stored inventory -> rules -> findings, each linked
to its device (the page an alert jumps to).

Findings then take the usual path (risk score, SLA, suppression, storage).
An audit that could not check everything says so with an informational
finding: a silent gap would read as "all clear".
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from app.inventory.audit.auditor import AuditOutcome, DeviceAuditor
from app.inventory.audit.base import AuditIssue, ReferenceData
from app.inventory.domain import Device
from app.scanner.context import stable_fingerprint
from app.scanner.plugins.base import Finding

PLUGIN_PREFIX = "inventory."
INCOMPLETE_AUDIT_RULE = "audit_incomplete"


@dataclass(frozen=True)
class AuditedDevice:
    id: int  # stored device id, target of the device page
    device: Device


@dataclass(frozen=True)
class AuditRun:
    connection_id: int
    job_id: int
    audited_at: datetime
    devices: int
    issues: int
    warnings: tuple[str, ...] = ()


class AuditStore(Protocol):
    def devices_to_audit(self, connection_id: int) -> list[AuditedDevice]:
        """Active devices of the connection, with their apps."""

    def record_audit(self, run: AuditRun) -> None: ...


class InventoryAudit:
    def __init__(
        self,
        store: AuditStore,
        auditor: DeviceAuditor,
        reference: Callable[[int], ReferenceData],  # by workspace
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._store = store
        self._auditor = auditor
        self._reference = reference
        self._clock = clock

    def run(self, connection_id: int, workspace_id: int, job_id: int) -> list[Finding]:
        audited = self._store.devices_to_audit(connection_id)
        outcome = self._auditor.audit([entry.device for entry in audited], self._reference(workspace_id))
        findings = [
            device_finding(issue, entry)
            for entry in audited
            for issue in outcome.issues.get(entry.device.external_id, ())
        ]
        warnings = audit_warnings(outcome)
        if warnings:
            findings.append(incomplete_audit_finding(connection_id, warnings))
        self._store.record_audit(AuditRun(
            connection_id=connection_id,
            job_id=job_id,
            audited_at=self._clock(),
            devices=len(audited),
            issues=outcome.issue_count,
            warnings=warnings,
        ))
        return findings


def device_finding(issue: AuditIssue, audited: AuditedDevice) -> Finding:
    device = audited.device
    return Finding(
        plugin_id=PLUGIN_PREFIX + issue.rule,
        title=f"{issue.title} — {device.name}",
        severity=issue.severity,
        description=issue.description,
        remediation=issue.remediation,
        evidence=_evidence(device, issue.evidence),
        # Stable across audits (no version in it): the alert policy and the
        # suppression list recognise the same issue from one day to the next.
        fingerprint=stable_fingerprint("inventory", issue.rule, device.external_id, issue.subject),
        references=list(issue.references),
        cvss=issue.cvss,
        cve=issue.cve,
        is_kev=issue.is_kev,
        confidence=issue.confidence,
        affected=device.name,
        device_id=audited.id,
    )


def audit_warnings(outcome: AuditOutcome) -> tuple[str, ...]:
    warnings = []
    if outcome.unavailable_products:
        products = ", ".join(sorted(outcome.unavailable_products))
        warnings.append(f"Support lifecycle unavailable (endoflife.date) for: {products}. "
                        "End-of-support checks were skipped for them; versions were compared with the fleet only.")
    if outcome.rule_errors:
        warnings.append(f"{outcome.rule_errors} audit checks failed on unexpected device data (see the worker logs).")
    return tuple(warnings) + outcome.notes


def incomplete_audit_finding(connection_id: int, warnings: Sequence[str]) -> Finding:
    return Finding(
        plugin_id=PLUGIN_PREFIX + INCOMPLETE_AUDIT_RULE,
        title="Device audit incomplete",
        severity="info",
        description="Part of the device audit could not run: a device without issues is not necessarily up to date.\n\n"
                    + "\n".join(f"- {warning}" for warning in warnings),
        remediation="Fix the causes listed above (the worker must reach https://endoflife.date; NVD and CISA KEV "
                    "datasets must be loaded), then run the inventory sync again.",
        fingerprint=stable_fingerprint("inventory", INCOMPLETE_AUDIT_RULE, connection_id),
    )


def _evidence(device: Device, details: Sequence[tuple[str, str]]) -> str:
    lines = [("Device", device.name)]
    if device.user_principal_name:
        lines.append(("User", device.user_principal_name))
    if device.serial_number:
        lines.append(("Serial number", device.serial_number))
    if device.last_check_in_at:
        lines.append(("Last check-in", device.last_check_in_at.isoformat(timespec="minutes")))
    lines += details
    return "\n".join(f"{label}: {value}" for label, value in lines)
