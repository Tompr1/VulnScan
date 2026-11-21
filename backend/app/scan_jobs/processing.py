"""
Finding processing — turns raw plugin findings into scored findings ready to
be persisted: confidence capping, CVSS enrichment, filtering, risk score,
final severity, SLA and compliance mapping.

Pure domain logic: every external lookup is injected, so the whole pipeline
is unit-testable without a database.
"""
from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from app.risk.risk_engine import DEFAULT_CRITICALITY, RiskFactors, compute_risk
from app.risk.severity import Severity
from app.risk.sla_engine import assign_sla_days, sla_policy_text
from app.scan_jobs.filtering import FindingFilterPolicy
from app.scan_jobs.validation import FindingValidation, ValidationState
from app.scanner.plugins.base import Finding

logger = logging.getLogger(__name__)

_MAX_CVSS = 10.0


class CvssEnricher(Protocol):
    def enrich_finding_cvss(self, cve_id: str, current_cvss: float | None) -> tuple[float | None, float]:
        """Best known CVSS for ``cve_id`` and the confidence it deserves."""


ComplianceMapper = Callable[[str | None, str], list[str]]


@dataclass(frozen=True)
class ProcessedFinding:
    plugin_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    evidence: str
    fingerprint: str
    references: list[str]
    cvss: float | None
    risk_score: float
    confidence: float
    sla_days: int
    compliance: list[str]
    is_kev: bool
    cve: str | None
    device_id: int | None = None


@dataclass(frozen=True)
class ProcessingReport:
    total: int
    saved: list[ProcessedFinding] = field(default_factory=list)
    dropped: int = 0

    def severity_counts(self) -> dict[Severity, int]:
        counts = Counter(f.severity for f in self.saved)
        return {severity: counts.get(severity, 0) for severity in Severity}


class FindingProcessor:
    def __init__(
        self,
        filter_policy: FindingFilterPolicy,
        compliance_mapper: ComplianceMapper,
        criticality: int = DEFAULT_CRITICALITY,
        cvss_enricher: CvssEnricher | None = None,
    ) -> None:
        self._filter = filter_policy
        self._map_compliance = compliance_mapper
        self._criticality = criticality
        self._enricher = cvss_enricher

    @property
    def min_confidence(self) -> float:
        return self._filter.min_confidence

    def process(self, findings: Sequence[Finding], default_target: str, suppressed: Collection[str]) -> ProcessingReport:
        validated = _validated_cves(findings, default_target)
        saved: list[ProcessedFinding] = []
        dropped = 0
        for finding in findings:
            if finding.fingerprint in suppressed:
                continue
            validation = FindingValidation.from_evidence(finding.evidence)
            if _is_superseded(finding, validation, default_target, validated):
                logger.info("Skipping %s duplicate of a validated %s", validation.state_label, finding.cve)
                continue

            cvss, confidence = self._score_inputs(finding, validation)
            reason = self._filter.drop_reason(validation, confidence, finding.severity or "")
            if reason:
                logger.info("Dropping finding %r: %s", finding.title, reason)
                dropped += 1
                continue
            saved.append(self._build(finding, validation, cvss, confidence))
        return ProcessingReport(total=len(findings), saved=saved, dropped=dropped)

    def _score_inputs(self, finding: Finding, validation: FindingValidation) -> tuple[float | None, float]:
        cap = validation.state.confidence_cap if validation.state else None
        confidence = _cap(_confidence_of(finding), cap)
        cvss = _valid_cvss(finding.cvss)

        if self._enricher and finding.cve and finding.cve.startswith("CVE-"):
            enriched_cvss, enriched_confidence = self._enricher.enrich_finding_cvss(finding.cve, cvss)
            if enriched_cvss is not None:
                cvss = _valid_cvss(enriched_cvss)
                confidence = _cap(max(confidence, enriched_confidence), cap)

        if cvss is None:
            # No CVE-backed score (e.g. "Exposed debug console"): derive one
            # from the plugin's severity, which is still meaningful.
            plugin_severity = Severity.parse(finding.severity)
            cvss = plugin_severity.baseline_cvss if plugin_severity else None
        return cvss, confidence

    def _build(self, finding: Finding, validation: FindingValidation, cvss: float | None, confidence: float) -> ProcessedFinding:
        risk = compute_risk(
            RiskFactors(
                cvss=cvss,
                kev=finding.is_kev,
                exploit_known=finding.is_kev,
                criticality=self._criticality,
                confidence=confidence,
                plugin_severity=Severity.parse(finding.severity),
            )
        )
        severity = Severity.from_score(risk)
        return ProcessedFinding(
            plugin_id=finding.plugin_id,
            title=finding.title,
            severity=severity,
            description=finding.description or "",
            remediation=_remediation(finding, validation, severity),
            evidence=finding.evidence or "",
            fingerprint=finding.fingerprint,
            references=list(finding.references or []),
            cvss=cvss,
            risk_score=risk,
            confidence=confidence,
            sla_days=assign_sla_days(severity),
            compliance=self._map_compliance(finding.cve, finding.plugin_id),
            is_kev=finding.is_kev,
            cve=finding.cve if finding.cve and finding.cve.startswith("CVE-") else None,
            device_id=finding.device_id,
        )


def _remediation(finding: Finding, validation: FindingValidation, severity: Severity) -> str:
    note = validation.state.remediation_note(validation.method) if validation.state else None
    parts = (note, finding.remediation, sla_policy_text(severity))
    return "\n\n".join(part for part in parts if part)


def _validated_cves(findings: Sequence[Finding], default_target: str) -> set[tuple[str, str]]:
    """(target, CVE) pairs confirmed by at least one validated finding."""
    return {
        (finding.affected or default_target, finding.cve)
        for finding in findings
        if finding.cve and FindingValidation.from_evidence(finding.evidence).state is ValidationState.VALIDATED
    }


def _is_superseded(
    finding: Finding, validation: FindingValidation, default_target: str, validated: set[tuple[str, str]]
) -> bool:
    """A weaker finding for a CVE that another finding already validated."""
    state = validation.state
    return (
        state is not None
        and state.is_weaker_than_validated
        and bool(finding.cve)
        and (finding.affected or default_target, finding.cve) in validated
    )


def _confidence_of(finding: Finding) -> float:
    if finding.confidence is None:
        return 1.0
    return max(0.0, min(float(finding.confidence), 1.0))


def _cap(confidence: float, cap: float | None) -> float:
    return confidence if cap is None else min(confidence, cap)


def _valid_cvss(value: float | None) -> float | None:
    """A plugin or dataset CVSS outside 0-10 is treated as unknown."""
    if value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not 0.0 <= score <= _MAX_CVSS:
        logger.warning("Ignoring out-of-range CVSS score %r", value)
        return None
    return score
