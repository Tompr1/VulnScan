"""
What changed between two inventories — pure functions, no I/O.

The journal feeds the device page ("Chrome 127 -> 128 on 12/11") and, later,
the "new detections only" alert policy.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from app.inventory.domain import Device, InstalledApp


class ChangeKind(StrEnum):
    DEVICE_ENROLLED = "device_enrolled"
    DEVICE_REMOVED = "device_removed"
    OS_UPDATED = "os_updated"
    APP_INSTALLED = "app_installed"
    APP_REMOVED = "app_removed"
    APP_UPDATED = "app_updated"


@dataclass(frozen=True)
class DeviceChange:
    device_external_id: str
    kind: ChangeKind
    subject: str
    before: str | None = None
    after: str | None = None


def diff_inventory(previous: Mapping[str, Device], current: Sequence[Device]) -> list[DeviceChange]:
    """Changes from the previous inventory (by external id) to the current one."""
    changes = [change for device in current for change in diff_device(previous.get(device.external_id), device)]
    current_ids = {device.external_id for device in current}
    changes += [
        DeviceChange(external_id, ChangeKind.DEVICE_REMOVED, device.name)
        for external_id, device in previous.items()
        if external_id not in current_ids
    ]
    return changes


def diff_device(before: Device | None, after: Device) -> list[DeviceChange]:
    """A new device only records its enrolment: its initial software is the
    baseline, not a list of changes."""
    if before is None:
        return [DeviceChange(after.external_id, ChangeKind.DEVICE_ENROLLED, after.name)]
    changes = []
    if before.os_version != after.os_version:
        changes.append(DeviceChange(after.external_id, ChangeKind.OS_UPDATED, after.os_name or "OS", before.os_version, after.os_version))
    changes += _app_changes(after.external_id, before.apps, after.apps)
    return changes


def _app_changes(device_id: str, before: Iterable[InstalledApp], after: Iterable[InstalledApp]) -> list[DeviceChange]:
    old, new = _versions_by_app(before), _versions_by_app(after)
    changes = []
    for key in sorted(old.keys() | new.keys()):
        old_versions, new_versions = old.get(key, {}), new.get(key, {})
        if set(old_versions) == set(new_versions):
            continue
        if len(old_versions) == 1 and len(new_versions) == 1:
            [old_version] = old_versions
            [(new_version, name)] = new_versions.items()
            changes.append(DeviceChange(device_id, ChangeKind.APP_UPDATED, name, old_version or None, new_version or None))
            continue
        for version in sorted(set(old_versions) - set(new_versions)):
            changes.append(DeviceChange(device_id, ChangeKind.APP_REMOVED, old_versions[version], before=version or None))
        for version in sorted(set(new_versions) - set(old_versions)):
            changes.append(DeviceChange(device_id, ChangeKind.APP_INSTALLED, new_versions[version], after=version or None))
    return changes


def _versions_by_app(apps: Iterable[InstalledApp]) -> dict[str, dict[str, str]]:
    """{app key: {version: display name}} — an app may be installed in
    several versions side by side (e.g. Visual C++ runtimes)."""
    grouped: dict[str, dict[str, str]] = defaultdict(dict)
    for app in apps:
        grouped[app.key][app.version or ""] = app.name
    return grouped
