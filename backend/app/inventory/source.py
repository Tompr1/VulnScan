"""
The contract every fleet manager connector implements.

Intune today; GLPI or Fleet later are new classes satisfying this protocol,
checked by the same contract tests — nothing else changes.
"""
from __future__ import annotations

from typing import Protocol

from app.inventory.domain import InventorySnapshot


class InventorySource(Protocol):
    name: str

    def check_access(self) -> None:
        """Raise if the credentials or permissions do not work."""

    def collect(self) -> InventorySnapshot:
        """Every managed device with its installed applications."""
