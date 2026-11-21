"""
Severity — the single source of truth for CVSS v3 severity bands.

Every module that needs to turn a score into a label (or a label back into a
representative score) goes through this type. Before it existed the band
thresholds were copied in three modules and the "baseline score" table in two,
and the copies had drifted apart (medium = 5.0 in one, 5.5 in the other).
"""
from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_score(cls, score: float | None) -> Severity:
        """Map a CVSS v3 / risk score (0-10) to its severity band."""
        if score is None:
            return cls.INFO
        for severity in _BANDS_HIGHEST_FIRST:
            if score >= severity.floor:
                return severity
        return cls.INFO

    @classmethod
    def parse(cls, label: str | None) -> Severity | None:
        """Case-insensitive label parsing. Unknown or empty labels give None."""
        if not label:
            return None
        try:
            return cls(label.strip().lower())
        except ValueError:
            return None

    @property
    def floor(self) -> float:
        """Lowest score that still belongs to this band (CVSS v3 spec)."""
        return _FLOOR[self]

    @property
    def baseline_cvss(self) -> float:
        """Representative score for findings that have a severity but no CVSS.

        Midpoint of each band, so that ``Severity.from_score(s.baseline_cvss) is s``.
        """
        return _BASELINE[self]


_FLOOR: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 0.1,
    Severity.INFO: 0.0,
}

_BASELINE: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}

_BANDS_HIGHEST_FIRST = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
