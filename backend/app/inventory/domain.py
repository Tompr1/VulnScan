"""
Inventory domain — what a fleet manager tells us about a device.

Source-independent: Intune today, GLPI or Fleet tomorrow all produce these
objects, so the sync, the audit rules and the API never depend on a vendor's
data model. Objects validate themselves: an invalid one cannot be built.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Platform(StrEnum):
    WINDOWS = "windows"
    MACOS = "macos"
    IOS = "ios"
    ANDROID = "android"
    LINUX = "linux"
    OTHER = "other"

    @classmethod
    def from_os_name(cls, os_name: str | None) -> Platform:
        """Map an OS name as reported by a fleet manager ("Windows",
        "iPadOS", "AndroidForWork", "Ubuntu"…)."""
        name = (os_name or "").strip().lower()
        for prefixes, platform in _OS_PREFIXES:
            if name.startswith(prefixes):
                return platform
        return cls.OTHER


_OS_PREFIXES: tuple[tuple[tuple[str, ...], Platform], ...] = (
    (("windows",), Platform.WINDOWS),
    (("macos", "mac os", "osx", "os x"), Platform.MACOS),
    (("ios", "ipados"), Platform.IOS),
    (("android",), Platform.ANDROID),
    (("linux", "ubuntu", "rhel", "red hat", "debian", "fedora", "centos"), Platform.LINUX),
)


@dataclass(frozen=True)
class InstalledApp:
    name: str
    version: str | None = None
    publisher: str | None = None

    def __post_init__(self) -> None:
        name = (self.name or "").strip()
        if not name:
            raise ValueError("an installed application needs a name")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", (self.version or "").strip() or None)
        object.__setattr__(self, "publisher", (self.publisher or "").strip() or None)

    @property
    def key(self) -> str:
        """Identity across inventories, regardless of the version."""
        return self.name.lower()


@dataclass(frozen=True)
class Device:
    """A managed device. ``external_id`` is the fleet manager's own id."""

    external_id: str
    name: str
    platform: Platform
    os_name: str = ""
    os_version: str | None = None
    model: str | None = None
    manufacturer: str | None = None
    serial_number: str | None = None
    user_principal_name: str | None = None
    ownership: str | None = None  # company / personal
    compliance_state: str | None = None
    is_encrypted: bool | None = None
    security_patch_level: str | None = None  # Android
    last_check_in_at: datetime | None = None
    apps: tuple[InstalledApp, ...] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if not (self.external_id or "").strip():
            raise ValueError("a device needs the id given by its fleet manager")
        if not (self.name or "").strip():
            raise ValueError(f"device {self.external_id} has no name")
        if self.last_check_in_at is not None and self.last_check_in_at.tzinfo is None:
            raise ValueError("last_check_in_at must be timezone-aware")


@dataclass(frozen=True)
class InventorySnapshot:
    """Everything one collection returned. ``skipped`` counts the source
    records that were invalid and left out (never silently)."""

    source: str
    devices: tuple[Device, ...]
    collected_at: datetime
    skipped_devices: int = 0
    skipped_apps: int = 0

    @property
    def app_count(self) -> int:
        return sum(len(d.apps) for d in self.devices)
