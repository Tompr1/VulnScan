"""
Which product, and which release line, an OS or an installed app is.

Fleet managers report free text ("10.0.22631.4317", "Mozilla Firefox (x64 fr)",
"Microsoft Office Professional Plus 2019 - fr-fr"). This module turns it into
an InstalledRelease (endoflife.date product + version) and picks the matching
SupportCycle. Covering a new application is one line in APP_PRODUCTS.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.inventory.audit.lifecycle import SupportCycle, leading_version
from app.inventory.domain import Device, InstalledApp, Platform


class CycleSelector(Protocol):
    def select(self, cycles: Sequence[SupportCycle], release: InstalledRelease) -> SupportCycle | None: ...


class VersionPrefixCycle:
    """The longest cycle whose dotted name starts the version:
    "3.12.4" -> "3.12", "131.0.6778.86" -> "131", "22.04.3" -> "22.04"."""

    def select(self, cycles: Sequence[SupportCycle], release: InstalledRelease) -> SupportCycle | None:
        parts = release.version.split(".")
        matching = [c for c in cycles if _is_prefix(c.name.split("."), parts)]
        return max(matching, key=lambda c: len(c.name.split(".")), default=None)


class WindowsBuildCycle:
    """Windows cycles share their build ("10.0.22631" for 11 23H2) across
    editions. Intune does not report the edition, so the Home/Pro line is
    preferred: its support ends first, Enterprise/Education get longer."""

    _EDITION_ORDER = ("w", "", "e")  # "-w" Home/Pro, no suffix, "-e" Enterprise

    def select(self, cycles: Sequence[SupportCycle], release: InstalledRelease) -> SupportCycle | None:
        build = ".".join(release.version.split(".")[:3])
        candidates = {_windows_edition(c.name): c for c in cycles if c.latest == build and _is_general_availability(c.name)}
        for edition in self._EDITION_ORDER:
            if edition in candidates:
                return candidates[edition]
        return None


class NameYearCycle:
    """Office is versioned by year in its name, not by its build number:
    "Microsoft Office Professional Plus 2019" -> cycle "2019" ("2021-ltsc"
    for an LTSC product)."""

    _YEAR = re.compile(r"\b(20\d\d)\b")

    def select(self, cycles: Sequence[SupportCycle], release: InstalledRelease) -> SupportCycle | None:
        match = self._YEAR.search(release.name)
        if not match:
            return None
        wanted = match.group(1) + ("-ltsc" if "ltsc" in release.name.lower() else "")
        return next((c for c in cycles if c.name == wanted), None)


@dataclass(frozen=True)
class Product:
    slug: str  # endoflife.date product
    title: str
    selector: CycleSelector = VersionPrefixCycle()
    note: str = ""

    @property
    def reference_url(self) -> str:
        return f"https://endoflife.date/{self.slug}"


@dataclass(frozen=True)
class InstalledRelease:
    product: Product
    version: str
    name: str = ""  # as reported, for name-versioned products

    def cycle_in(self, cycles: Sequence[SupportCycle]) -> SupportCycle | None:
        return self.product.selector.select(cycles, self)


WINDOWS = Product(
    "windows", "Windows", WindowsBuildCycle(),
    note="Intune does not report the Windows edition: dates are those of Home/Pro. "
         "Enterprise and Education editions are supported longer.",
)
MACOS = Product("macos", "macOS")
IOS = Product("ios", "iOS")
IPADOS = Product("ipados", "iPadOS")
ANDROID = Product("android", "Android")
_LINUX_DISTROS = (
    (("ubuntu",), Product("ubuntu", "Ubuntu")),
    (("red hat", "rhel"), Product("rhel", "Red Hat Enterprise Linux")),
    (("debian",), Product("debian", "Debian")),
    (("fedora",), Product("fedora", "Fedora")),
)

# Matched against the lower-cased display name reported by the fleet manager.
APP_PRODUCTS: tuple[tuple[re.Pattern[str], Product], ...] = tuple(
    (re.compile(pattern), product)
    for pattern, product in (
        (r"^google chrome$", Product("chrome", "Google Chrome")),
        (r"^mozilla firefox\b", Product("firefox", "Mozilla Firefox")),
        (r"^notepad\+\+", Product("notepad-plus-plus", "Notepad++")),
        (r"^libreoffice\b", Product("libreoffice", "LibreOffice")),
        (r"^git( version [\d.]+)?$", Product("git", "Git")),
        (r"^node\.js\b", Product("nodejs", "Node.js")),
        (r"^powershell 7", Product("powershell", "PowerShell")),
        (r"^(microsoft )?visual studio (community|professional|enterprise|build tools) 20\d\d", Product("visual-studio", "Visual Studio")),
        (r"^microsoft office\b.*\b20\d\d\b", Product("office", "Microsoft Office", NameYearCycle())),
    )
)


def identify_os(device: Device) -> InstalledRelease | None:
    version = leading_version(device.os_version)
    if not version:
        return None
    product = _os_product(device)
    return InstalledRelease(product, version, device.os_name) if product else None


def identify_app(app: InstalledApp) -> InstalledRelease | None:
    if not app.version:
        return None
    name = app.name.lower()
    for pattern, product in APP_PRODUCTS:
        if pattern.search(name):
            return InstalledRelease(product, app.version, app.name)
    return None


def _os_product(device: Device) -> Product | None:
    if device.platform is Platform.WINDOWS:
        return WINDOWS
    if device.platform is Platform.MACOS:
        return MACOS
    if device.platform is Platform.IOS:
        return IPADOS if device.os_name.lower().startswith("ipados") else IOS
    if device.platform is Platform.ANDROID:
        return ANDROID
    if device.platform is Platform.LINUX:
        # "Linux" alone does not say which distribution's calendar applies.
        text = f"{device.os_name} {device.os_version or ''}".lower()
        return next((product for keys, product in _LINUX_DISTROS if any(k in text for k in keys)), None)
    return None


def _is_prefix(prefix: list[str], parts: list[str]) -> bool:
    return len(prefix) <= len(parts) and parts[: len(prefix)] == prefix


def _windows_edition(cycle_name: str) -> str:
    suffix = cycle_name.rsplit("-", 1)[-1]
    return suffix if suffix in ("w", "e") else ""


def _is_general_availability(cycle_name: str) -> bool:
    """LTSC and IoT lines are separate products with their own builds."""
    return not any(marker in cycle_name for marker in ("-lts", "-iot"))
