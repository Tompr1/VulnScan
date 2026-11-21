"""
Validation state of a finding.

Plugins describe how far they validated a finding with ``key=value`` pairs in
the evidence text (``validation_state=provisional validation_method=...``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_EVIDENCE_PAIR = re.compile(r"\b([a-z_]+)=((?:\"[^\"]*\")|\S+)", re.IGNORECASE)
_LOCAL_ONLY_METHOD = "package_version_match_local_only"
_NOT_NETWORK_FACING = "network_facing=no"


def parse_evidence_pairs(evidence: str | None) -> dict[str, str]:
    """``key=value`` pairs of an evidence string (keys lower-cased)."""
    return {key.lower(): value.strip('"') for key, value in _EVIDENCE_PAIR.findall(evidence or "")}


class ValidationState(StrEnum):
    VALIDATED = "validated"
    PROVISIONAL = "provisional"
    LIKELY_PATCHED = "likely_patched"
    LIKELY_NOT_EXPLOITABLE = "likely_not_exploitable"
    PROBE_NEGATIVE = "probe_negative"

    @property
    def confidence_cap(self) -> float | None:
        """Highest confidence a finding in this state may have (None: uncapped)."""
        return _CONFIDENCE_CAP.get(self)

    @property
    def is_weaker_than_validated(self) -> bool:
        return self is not ValidationState.VALIDATED

    def remediation_note(self, method: str) -> str | None:
        """Warning prepended to the remediation of a not-validated finding."""
        template = _REMEDIATION_NOTE.get(self)
        if template is None:
            return None
        return template.format(method=method or _DEFAULT_METHOD[self])


_CONFIDENCE_CAP: dict[ValidationState, float] = {
    ValidationState.LIKELY_PATCHED: 0.10,  # distro backport detected
    ValidationState.LIKELY_NOT_EXPLOITABLE: 0.15,  # active test found nothing
    ValidationState.PROBE_NEGATIVE: 0.20,  # endpoint probe was negative
    ValidationState.PROVISIONAL: 0.35,  # version-only match
}

_DEFAULT_METHOD: dict[ValidationState, str] = {
    ValidationState.LIKELY_PATCHED: "",
    ValidationState.LIKELY_NOT_EXPLOITABLE: "owasp_cross_reference",
    ValidationState.PROBE_NEGATIVE: "endpoint_probe",
    ValidationState.PROVISIONAL: "version correlation",
}

_REMEDIATION_NOTE: dict[ValidationState, str] = {
    ValidationState.LIKELY_PATCHED: (
        "[LIKELY PATCHED] This package version contains a distro-specific patch suffix "
        "indicating a backported security fix. The upstream version appears vulnerable, "
        "but the distro vendor has likely applied the relevant patches. "
        "Verify with: apt-cache policy <package> or rpm -q --changelog <package>."
    ),
    ValidationState.LIKELY_NOT_EXPLOITABLE: (
        "[LOW CONFIDENCE] Active OWASP scanning tested the relevant vulnerability category "
        "and found no evidence of exploitation on this target. The version correlation suggests "
        "a potential vulnerability, but runtime testing did not confirm it. "
        "Method: {method}."
    ),
    ValidationState.PROBE_NEGATIVE: (
        "[PROBE NEGATIVE] An endpoint probe tested for the specific attack surface "
        "associated with this CVE but did not find it accessible. The vulnerability "
        "may not be exploitable in the current configuration. "
        "Method: {method}."
    ),
    ValidationState.PROVISIONAL: (
        "[VALIDATION] This is a provisional version correlation, not a confirmed vulnerable condition. "
        "Validate against vendor release advisories, package build provenance, runtime exposure, "
        "and feature/config state before treating it as exploitable. Method: {method}."
    ),
}


@dataclass(frozen=True)
class FindingValidation:
    """What a finding's evidence says about its validation."""

    state_label: str
    method: str
    not_network_facing: bool

    @classmethod
    def from_evidence(cls, evidence: str | None) -> FindingValidation:
        pairs = parse_evidence_pairs(evidence)
        return cls(
            state_label=pairs.get("validation_state", "").lower(),
            method=pairs.get("validation_method", "").lower(),
            not_network_facing=_NOT_NETWORK_FACING in (evidence or ""),
        )

    @property
    def state(self) -> ValidationState | None:
        try:
            return ValidationState(self.state_label)
        except ValueError:
            return None

    @property
    def is_local_only(self) -> bool:
        """Package found on disk but not reachable from the network."""
        return self.not_network_facing and self.method == _LOCAL_ONLY_METHOD
