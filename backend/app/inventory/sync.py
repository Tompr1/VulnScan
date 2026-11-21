"""
Inventory synchronisation: store a fresh snapshot and journal what changed.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.inventory.changes import ChangeKind, DeviceChange, diff_inventory
from app.inventory.domain import Device, InventorySnapshot


class InventoryRepository(Protocol):
    def active_devices(self, connection_id: int) -> dict[str, Device]:
        """Devices of the last snapshot (removed ones excluded), by external id."""

    def save_snapshot(
        self, connection_id: int, workspace_id: int, snapshot: InventorySnapshot, changes: Sequence[DeviceChange]
    ) -> None: ...


@dataclass(frozen=True)
class InventorySyncResult:
    devices: int
    apps: int
    enrolled: int
    removed: int
    changes: int
    skipped_devices: int
    skipped_apps: int

    def summary(self) -> str:
        skipped = self.skipped_devices + self.skipped_apps
        return (
            f"{self.devices} devices, {self.apps} apps, {self.enrolled} enrolled, {self.removed} removed, "
            f"{self.changes} changes" + (f", {skipped} invalid records skipped" if skipped else "")
        )


class InventorySync:
    def __init__(self, repository: InventoryRepository) -> None:
        self._repository = repository

    def apply(self, connection_id: int, workspace_id: int, snapshot: InventorySnapshot) -> InventorySyncResult:
        previous = self._repository.active_devices(connection_id)
        changes = diff_inventory(previous, snapshot.devices)
        self._repository.save_snapshot(connection_id, workspace_id, snapshot, changes)
        return InventorySyncResult(
            devices=len(snapshot.devices),
            apps=snapshot.app_count,
            enrolled=sum(c.kind is ChangeKind.DEVICE_ENROLLED for c in changes),
            removed=sum(c.kind is ChangeKind.DEVICE_REMOVED for c in changes),
            changes=len(changes),
            skipped_devices=snapshot.skipped_devices,
            skipped_apps=snapshot.skipped_apps,
        )
