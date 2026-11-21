"""
Scan time budget — how long the whole scan, and each plugin, may run.

The budget keeps a scan inside the RQ job timeout: RQ SIGKILLs the worker at
that point and every collected finding would be lost.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.scanner.target import ScanType


@dataclass(frozen=True)
class ScanBudget:
    total_seconds: float
    # Kept free for post-scan processing (enrichment, DB writes).
    reserve_seconds: float = 30.0
    # Below this remaining time no further plugin is started.
    min_plugin_seconds: float = 5.0
    # No single plugin may use more than this share of the total budget, so
    # one slow plugin cannot starve the critical ones that run after it.
    max_plugin_share: float = 0.20
    # External targets are slower to answer: their plugins get more time.
    external_timeout_factor: float = 1.5
    external_min_timeout: float = 20.0
    # Extra time given to a plugin to honour its own timeout before it is killed.
    kill_grace_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.total_seconds <= 0:
            raise ValueError("total_seconds must be positive")
        if not 0 < self.max_plugin_share <= 1:
            raise ValueError("max_plugin_share must be in (0, 1]")

    def remaining(self, elapsed: float) -> float:
        return self.total_seconds - elapsed - self.reserve_seconds

    def is_exhausted(self, elapsed: float) -> bool:
        return self.remaining(elapsed) <= self.min_plugin_seconds

    def plugin_timeout(self, declared_timeout: float, scan_type: ScanType, elapsed: float) -> float:
        """Timeout a plugin is told to respect, capped by what is left."""
        timeout = declared_timeout
        if scan_type is ScanType.EXTERNAL:
            timeout = max(timeout * self.external_timeout_factor, self.external_min_timeout)
        return min(timeout, self.total_seconds * self.max_plugin_share, self.remaining(elapsed))

    def kill_timeout(self, plugin_timeout: float) -> float:
        """Hard limit after which the engine abandons the plugin."""
        return plugin_timeout + self.kill_grace_seconds
