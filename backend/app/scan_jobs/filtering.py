"""
Finding filter policy — decides which findings are not worth saving.

Configurable per profile through ``options_json``::

    {"filtering": {"min_confidence": 0.20,
                   "drop_states": ["likely_patched"],
                   "drop_local_only": true}}
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.scan_jobs.validation import FindingValidation

logger = logging.getLogger(__name__)

# 0.20 drops likely-patched (0.10) and local-only (0.15) findings, and keeps
# negative probes (0.20), provisional matches (0.35) and validated ones (1.0).
DEFAULT_MIN_CONFIDENCE = 0.20
DEFAULT_DROP_STATES = frozenset({"likely_patched"})


@dataclass(frozen=True)
class FindingFilterPolicy:
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    drop_states: frozenset[str] = DEFAULT_DROP_STATES
    drop_local_only: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError(f"min_confidence must be between 0 and 1, got {self.min_confidence}")

    @classmethod
    def from_profile_options(cls, options: Mapping[str, Any]) -> FindingFilterPolicy:
        """Parse user-editable profile options; invalid values keep their default."""
        raw = options.get("filtering")
        if not isinstance(raw, Mapping):
            return cls()
        return cls(
            min_confidence=_parse_confidence(raw.get("min_confidence", DEFAULT_MIN_CONFIDENCE)),
            drop_states=_parse_states(raw.get("drop_states", DEFAULT_DROP_STATES)),
            drop_local_only=bool(raw.get("drop_local_only", True)),
        )

    def drop_reason(self, validation: FindingValidation, confidence: float, plugin_severity: str) -> str | None:
        """Why the finding must be dropped, or None to keep it."""
        if validation.state_label in self.drop_states:
            return f"validation state {validation.state_label}"
        if self.drop_local_only and validation.is_local_only:
            return "local-only package"
        # Informational findings are not vulnerabilities: confidence does not apply.
        if confidence < self.min_confidence and plugin_severity.lower() != "info":
            return f"confidence {confidence:.2f} < {self.min_confidence:.2f}"
        return None


def _parse_confidence(raw: Any) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid filtering.min_confidence %r — using default", raw)
        return DEFAULT_MIN_CONFIDENCE
    return max(0.0, min(value, 1.0))


def _parse_states(raw: Any) -> frozenset[str]:
    if isinstance(raw, str) or not hasattr(raw, "__iter__"):
        logger.warning("Invalid filtering.drop_states %r — using default", raw)
        return DEFAULT_DROP_STATES
    return frozenset(str(state).lower() for state in raw)
