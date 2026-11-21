"""
The fleet as a version reference: "PC-04 runs 7-Zip 19.00 while 24.08 is
deployed elsewhere".

Used when the vendor's latest release is unknown (option c: vendor first,
fleet otherwise). Guards against noise:
- a version only becomes the reference once ``min_devices`` run it, so one
  machine on a beta does not flag the rest of the fleet;
- an OS is compared within its release line (Windows 11 24H2 with 24H2):
  moving to a new release is an upgrade project, not a missed update, and
  the vendor lifecycle covers releases that lose support;
- an app is compared across versions of the same family, majors included:
  many vendors number by year (7-Zip 23.01 -> 24.08), so a new major is
  usually just the next release.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.inventory.audit.lifecycle import comparable, leading_version
from app.inventory.domain import Device, InstalledApp, Platform

_PARENTHESES = re.compile(r"\([^)]*\)")
_VERSION_TOKEN = re.compile(r"\bv?\d+(?:\.\d+)+\S*")
_ARCHITECTURE = re.compile(r"\b(?:x64|x86|amd64|arm64|64-bit|32-bit|64 bit|32 bit)\b")
_SPACES = re.compile(r"\s+")
_SEPARATORS = " -–—_,"

OsKey = tuple[Platform, str]  # (platform, release line)


def app_family(name: str) -> str:
    """The product an app name designates, whatever its version, architecture
    or language: "7-Zip 24.08 (x64)" -> "7-zip", "Microsoft Visual C++
    2015-2022 Redistributable (x64) - 14.38.33135" -> "microsoft visual c++
    2015-2022 redistributable"."""
    family = _PARENTHESES.sub(" ", name.lower())
    family = _VERSION_TOKEN.sub(" ", family)
    family = _ARCHITECTURE.sub(" ", family)
    return _SPACES.sub(" ", family).strip(_SEPARATORS)


def newest_apps(apps: Iterable[InstalledApp]) -> list[InstalledApp]:
    """One app per family: the newest readable version. A device keeping an
    old copy next to the new one (side-by-side runtimes) is judged on the new
    one; whether the old copy is vulnerable is a CVE question."""
    best: dict[str, tuple[InstalledApp, object]] = {}
    for app in apps:
        version = comparable(app.version)
        family = app_family(app.name)
        if version is None or not family:
            continue
        current = best.get(family)
        if current is None or version > current[1]:
            best[family] = (app, version)
    return [app for app, _ in best.values()]


def os_line(device: Device) -> OsKey | None:
    """The release line of the OS: the version without its last part, so
    "10.0.22631.4317" (Windows 11 23H2 build) -> "10.0.22631", "14.4.1" ->
    "14.4". A single-part version ("14" on Android) has no updates to compare."""
    version = comparable(leading_version(device.os_version))
    if version is None or len(version.release) < 2:
        return None
    return device.platform, ".".join(map(str, version.release[:-1]))


@dataclass(frozen=True)
class FleetVersion:
    version: str
    devices: int


class FleetBaseline:
    def __init__(self, apps: dict[str, FleetVersion], systems: dict[OsKey, FleetVersion]) -> None:
        self._apps = apps
        self._systems = systems

    @classmethod
    def of(cls, devices: Sequence[Device], min_devices: int = 2) -> FleetBaseline:
        if min_devices < 1:
            raise ValueError("min_devices must be at least 1")
        app_versions: dict[str, Counter[str]] = defaultdict(Counter)
        os_versions: dict[OsKey, Counter[str]] = defaultdict(Counter)
        for device in devices:
            for app in newest_apps(device.apps):
                app_versions[app_family(app.name)][app.version] += 1
            line = os_line(device)
            if line is not None:
                os_versions[line][leading_version(device.os_version)] += 1
        return cls(_newest(app_versions, min_devices), _newest(os_versions, min_devices))

    def newest_app(self, app: InstalledApp) -> FleetVersion | None:
        return self._apps.get(app_family(app.name))

    def newest_os(self, device: Device) -> FleetVersion | None:
        line = os_line(device)
        return self._systems.get(line) if line else None


def _newest(versions: dict, min_devices: int) -> dict:
    """Per key, the newest version run by at least ``min_devices`` devices."""
    newest = {}
    for key, counts in versions.items():
        widespread = [(comparable(v), v, n) for v, n in counts.items() if n >= min_devices]
        widespread = [entry for entry in widespread if entry[0] is not None]
        if widespread:
            _, version, count = max(widespread, key=lambda entry: entry[0])
            newest[key] = FleetVersion(version, count)
    return newest

