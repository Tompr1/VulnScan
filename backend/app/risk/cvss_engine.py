"""
CVSS helpers built on top of :class:`app.risk.severity.Severity`.

The two label/score functions are kept as thin string-based adapters because
route serializers and report generators work with raw ORM strings.
"""
from __future__ import annotations

import math

from app.risk.severity import Severity


def severity_from_score(score: float | None) -> str:
    """Convert a numeric CVSS / risk score to its severity label."""
    return Severity.from_score(score).value


def cvss_baseline_from_severity(severity: str | None) -> float | None:
    """Representative CVSS score for a severity label, or None if unknown.

    Used for plugin findings that have no CVE (e.g. "Missing HSTS header") so
    the UI does not show "—" for every non-CVE finding.
    """
    parsed = Severity.parse(severity)
    return parsed.baseline_cvss if parsed else None


# CVSS v3.1 base metric weights (specification, section 7.4).
_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_REQUIRED = {"N": 0.85, "L": 0.62, "H": 0.27}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_IMPACT_FACTOR = 6.42
_EXPLOITABILITY_FACTOR = 8.22
_MAX_SCORE = 10.0


def cvss_v3_vector_to_score(vector: str) -> float | None:
    """Approximate a CVSS v3 base score from its vector string.

    Scope-unchanged approximation only; use the ``cvss`` package when exact
    scores are needed. Returns None when the vector cannot be parsed.
    """
    metrics = _parse_vector(vector)
    if metrics is None:
        return None

    impact_subscore = 1 - (
        (1 - _IMPACT.get(metrics.get("C", "N"), 0.0))
        * (1 - _IMPACT.get(metrics.get("I", "N"), 0.0))
        * (1 - _IMPACT.get(metrics.get("A", "N"), 0.0))
    )
    if impact_subscore == 0:
        return 0.0

    exploitability = (
        _EXPLOITABILITY_FACTOR
        * _ATTACK_VECTOR.get(metrics.get("AV", "N"), 0.85)
        * _ATTACK_COMPLEXITY.get(metrics.get("AC", "L"), 0.77)
        * _PRIVILEGES_REQUIRED.get(metrics.get("PR", "N"), 0.85)
        * _USER_INTERACTION.get(metrics.get("UI", "N"), 0.85)
    )
    base = min(_IMPACT_FACTOR * impact_subscore + exploitability, _MAX_SCORE)
    return _round_up_one_decimal(base)


def _parse_vector(vector: str) -> dict[str, str] | None:
    if not isinstance(vector, str):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        if ":" in value:
            return None
        metrics[key] = value
    return metrics


def _round_up_one_decimal(value: float) -> float:
    return math.ceil(value * 10) / 10
