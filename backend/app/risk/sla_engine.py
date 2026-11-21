"""
SLA engine — remediation deadlines and the guidance text shown with them.

Thresholds follow common enterprise SLA policies. The scan engine used to keep
its own copy of this policy with different deadlines (7/14/30/60 days); this
module is now the only place where they are defined.
"""
from __future__ import annotations

from app.risk.severity import Severity

SLA_DAYS: dict[Severity, int] = {
    Severity.CRITICAL: 2,
    Severity.HIGH: 7,
    Severity.MEDIUM: 30,
    Severity.LOW: 90,
    Severity.INFO: 365,
}

_GUIDANCE: dict[Severity, str] = {
    Severity.CRITICAL: (
        "Prioritize patching immediately. Apply vendor-provided fixes and consider "
        "temporary mitigations while permanent fixes are deployed."
    ),
    Severity.HIGH: (
        "Apply available patches promptly, review vendor advisories, and implement "
        "compensating controls if immediate patching is not feasible."
    ),
    Severity.MEDIUM: (
        "Plan patching during the next maintenance window. Review if compensating "
        "controls are already in place."
    ),
    Severity.LOW: (
        "Address during regular patching cycles. Document any accepted risk if "
        "remediation is deferred."
    ),
}


def assign_sla_days(severity: Severity | str) -> int:
    """Number of days allowed to remediate a finding of the given severity."""
    parsed = severity if isinstance(severity, Severity) else Severity.parse(severity)
    return SLA_DAYS[parsed or Severity.INFO]


def sla_policy_text(severity: Severity) -> str | None:
    """Remediation policy paragraph for a finding, None for informational ones."""
    if severity is Severity.INFO:
        return None
    return (
        f"[SLA POLICY] This is a {severity.value.upper()} severity vulnerability "
        f"with a {SLA_DAYS[severity]}-day remediation SLA. {_GUIDANCE[severity]}"
    )
