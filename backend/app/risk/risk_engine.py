"""
Risk scoring engine.

Computes a 0-10 composite risk score from CVSS, CISA KEV status, known
exploits, asset criticality and scanner confidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.risk.severity import Severity

MIN_CRITICALITY = 1
MAX_CRITICALITY = 5
DEFAULT_CRITICALITY = 2

_MAX_SCORE = 10.0
_UNKNOWN_BASE_SCORE = 5.0
_KEV_MULTIPLIER = 1.3
_EXPLOIT_KNOWN_MULTIPLIER = 1.15
_CRITICALITY_MULTIPLIER = {1: 0.8, 2: 1.0, 3: 1.1, 4: 1.2, 5: 1.3}
# Even a very unsure finding keeps a tenth of its weight.
_MIN_CONFIDENCE_WEIGHT = 0.1
# At or above this confidence a CVSS-backed finding never leaves its band:
# a CVSS 9.8 seen with confidence 0.9 stays critical instead of 8.82 (high).
_BAND_FLOOR_MIN_CONFIDENCE = 0.8


@dataclass(frozen=True)
class RiskFactors:
    """Validated inputs of the risk computation.

    Building one is the only way to call :func:`compute_risk`, so the scoring
    code never has to re-check its inputs.
    """

    cvss: float | None
    kev: bool = False
    exploit_known: bool = False
    criticality: int = DEFAULT_CRITICALITY
    confidence: float = 1.0
    plugin_severity: Severity | None = None

    def __post_init__(self) -> None:
        if self.cvss is not None and not 0.0 <= self.cvss <= _MAX_SCORE:
            raise ValueError(f"cvss must be between 0 and 10, got {self.cvss}")
        if not MIN_CRITICALITY <= self.criticality <= MAX_CRITICALITY:
            raise ValueError(
                f"criticality must be between {MIN_CRITICALITY} and {MAX_CRITICALITY}, "
                f"got {self.criticality}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be between 0 and 1, got {self.confidence}")


def compute_risk(factors: RiskFactors) -> float:
    """Return the composite risk score, rounded to two decimals."""
    score = _base_score(factors)
    score = min(score * _threat_multiplier(factors), _MAX_SCORE)
    score = min(score * _CRITICALITY_MULTIPLIER[factors.criticality], _MAX_SCORE)
    score *= max(factors.confidence, _MIN_CONFIDENCE_WEIGHT)
    score = max(score, _band_floor(factors))
    return round(min(score, _MAX_SCORE), 2)


def _base_score(factors: RiskFactors) -> float:
    if factors.cvss is not None:
        return factors.cvss
    if factors.plugin_severity is not None:
        return factors.plugin_severity.baseline_cvss
    return _UNKNOWN_BASE_SCORE


def _threat_multiplier(factors: RiskFactors) -> float:
    if factors.kev:
        return _KEV_MULTIPLIER
    if factors.exploit_known:
        return _EXPLOIT_KNOWN_MULTIPLIER
    return 1.0


def _band_floor(factors: RiskFactors) -> float:
    """Lowest score allowed when CVSS is authoritative and confidence is high."""
    if factors.cvss is None or factors.confidence < _BAND_FLOOR_MIN_CONFIDENCE:
        return 0.0
    return Severity.from_score(factors.cvss).floor


def parse_criticality(raw: object) -> int:
    """Parse an asset criticality coming from user-editable profile options.

    Anything that is not an integer falls back to the default, and integers
    are clamped into the supported 1-5 range.
    """
    try:
        value = int(raw)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return DEFAULT_CRITICALITY
    return max(MIN_CRITICALITY, min(value, MAX_CRITICALITY))
