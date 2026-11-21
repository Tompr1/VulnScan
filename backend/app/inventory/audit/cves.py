"""
Which known CVEs affect a device: its OS build and installed applications,
identified as NVD CPE products and matched against the catalog's version
ranges (app.cve.matcher), with CISA KEV for exploitation.

Identification is a curated table, checked against NVD (CPE dictionary and
the version ranges used by recent CVEs): a wrong CPE silently finds
nothing, a loose one floods false positives. Left out on purpose:
- Microsoft 365 Apps / Office, Java, Citrix Workspace: NVD gives no build
  range comparable with what Intune reports (versionless, "2016",
  "1.8.0 update_x", "2402" vs "24.2.0");
- Android: its CVEs are fixed by security patch level, not by version
  (AndroidPatchLevelRule covers it).
NVD entries naming no version at all are ignored for every product: they
cannot tell a patched device from a vulnerable one.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.cve.cpe import ANY, Cpe, CpeMatch, ProductKey
from app.cve.kev import InMemoryKevCatalog, KevCatalog, KevEntry
from app.cve.matcher import CveCatalog, CveRecord, InMemoryCveCatalog, ProductCandidate, find_vulnerabilities
from app.cve.version_cmp import parse as parse_version
from app.inventory.audit.lifecycle import leading_version
from app.inventory.domain import Device, Platform


@dataclass(frozen=True)
class SoftwareIdentity:
    """A product as NVD names it; some are filed under several CPEs."""

    title: str
    cpes: tuple[tuple[str, str, str], ...]  # (part, vendor, product)

    @property
    def key(self) -> str:
        """Stable identifier (finding subject): the first CPE."""
        _, vendor, product = self.cpes[0]
        return f"{vendor}:{product}"

    @property
    def product_keys(self) -> list[ProductKey]:
        return [Cpe(part, vendor, product).product_key for part, vendor, product in self.cpes]

    def candidates(self, version: str) -> list[ProductCandidate]:
        return [ProductCandidate(Cpe(part, vendor, product, version), version) for part, vendor, product in self.cpes]


def _app(title: str, *cpes: str) -> SoftwareIdentity:
    return SoftwareIdentity(title, tuple(("a", *cpe.split(":", 1)) for cpe in cpes))


# Matched against the lower-cased display name (Windows and macOS spellings).
APP_CPES: tuple[tuple[re.Pattern[str], SoftwareIdentity], ...] = tuple(
    (re.compile(pattern), identity)
    for pattern, identity in (
        (r"^google chrome$", _app("Google Chrome", "google:chrome")),
        (r"^microsoft edge$", _app("Microsoft Edge", "microsoft:edge_chromium")),
        # ESR apart: Firefox ranges ("< 139.0.4") would flag an up-to-date ESR 128.
        (r"^(mozilla )?firefox esr\b", _app("Mozilla Firefox ESR", "mozilla:firefox_esr")),
        (r"^(mozilla )?firefox\b", _app("Mozilla Firefox", "mozilla:firefox")),
        (r"^(mozilla )?thunderbird\b", _app("Mozilla Thunderbird", "mozilla:thunderbird")),
        (r"^7-zip\b", _app("7-Zip", "7-zip:7-zip")),
        (r"^notepad\+\+", _app("Notepad++", r"notepad-plus-plus:notepad\+\+")),
        (r"^vlc( media player)?$", _app("VLC media player", "videolan:vlc_media_player")),
        (r"^adobe acrobat reader\b", _app("Adobe Acrobat Reader", "adobe:acrobat_reader_dc", "adobe:acrobat_reader")),
        (r"^adobe acrobat\b(?!.*reader)", _app("Adobe Acrobat", "adobe:acrobat_dc", "adobe:acrobat")),
        (r"^(zoom workplace|zoom|zoom\.us)\b(?!.*(rooms|plugin|outlook|add-in))", _app("Zoom Workplace", "zoom:workplace_desktop", "zoom:zoom")),
        (r"^winrar\b", _app("WinRAR", "rarlab:winrar")),
        (r"^git( version [\d.]+)?$", _app("Git", "git-scm:git", "git_for_windows_project:git_for_windows")),
        (r"^wireshark\b", _app("Wireshark", "wireshark:wireshark")),
        (r"^microsoft visual studio code\b|^visual studio code$", _app("Visual Studio Code", "microsoft:visual_studio_code")),
        (r"^forticlient\b", _app("FortiClient", "fortinet:forticlient")),
        (r"^powershell 7", _app("PowerShell", "microsoft:powershell")),
        (r"^putty\b", _app("PuTTY", "simon_tatham:putty", "putty:putty")),
        (r"^winscp\b", _app("WinSCP", "winscp:winscp")),
        (r"^filezilla\b(?!.*server)", _app("FileZilla", "filezilla-project:filezilla_client")),
        (r"^keepass\b", _app("KeePass", "keepass:keepass")),
        (r"^node\.js\b", _app("Node.js", "nodejs:node.js")),
        (r"^teamviewer\b", _app("TeamViewer", "teamviewer:teamviewer")),
        (r"^anydesk\b", _app("AnyDesk", "anydesk:anydesk")),
        (r"^libreoffice\b", _app("LibreOffice", "libreoffice:libreoffice")),
        (r"^docker desktop\b", _app("Docker Desktop", "docker:desktop")),
        (r"^cisco (secure client|anyconnect)\b", _app("Cisco Secure Client", "cisco:secure_client", "cisco:anyconnect_secure_mobility_client")),
    )
)

# Windows releases are separate NVD products, ranged by full build number
# ("versionEndExcluding": "10.0.22631.6060").
WINDOWS_BUILDS: dict[str, tuple[str, str]] = {
    "10.0.17763": ("Windows 10 1809", "windows_10_1809"),
    "10.0.19042": ("Windows 10 20H2", "windows_10_20h2"),
    "10.0.19043": ("Windows 10 21H1", "windows_10_21h1"),
    "10.0.19044": ("Windows 10 21H2", "windows_10_21h2"),
    "10.0.19045": ("Windows 10 22H2", "windows_10_22h2"),
    "10.0.22000": ("Windows 11 21H2", "windows_11_21h2"),
    "10.0.22621": ("Windows 11 22H2", "windows_11_22h2"),
    "10.0.22631": ("Windows 11 23H2", "windows_11_23h2"),
    "10.0.26100": ("Windows 11 24H2", "windows_11_24h2"),
    "10.0.26200": ("Windows 11 25H2", "windows_11_25h2"),
}
MACOS = SoftwareIdentity("macOS", (("o", "apple", "macos"), ("o", "apple", "mac_os_x")))
IOS = SoftwareIdentity("iOS", (("o", "apple", "iphone_os"),))
IPADOS = SoftwareIdentity("iPadOS", (("o", "apple", "ipados"),))


@dataclass(frozen=True)
class InstalledSoftware:
    identity: SoftwareIdentity
    version: str
    name: str  # as reported by the fleet manager
    is_os: bool = False


def installed_software(device: Device) -> list[InstalledSoftware]:
    """The device's OS and applications that can be matched to CVEs. Every
    installed copy counts: an old copy left next to the new one is still
    exploitable."""
    found = []
    system = _operating_system(device)
    if system is not None:
        found.append(system)
    for app in device.apps:
        identity = identify_software(app.name)
        if identity is not None and app.version:
            found.append(InstalledSoftware(identity, app.version, app.name))
    return list(dict.fromkeys(found))  # same identity and version once


def identify_software(name: str) -> SoftwareIdentity | None:
    lowered = name.strip().lower()
    return next((identity for pattern, identity in APP_CPES if pattern.search(lowered)), None)


def _operating_system(device: Device) -> InstalledSoftware | None:
    version = leading_version(device.os_version)
    if not version:
        return None
    if device.platform is Platform.WINDOWS:
        release = WINDOWS_BUILDS.get(".".join(version.split(".")[:3]))
        if release is None:
            return None
        title, product = release
        return InstalledSoftware(SoftwareIdentity(title, (("o", "microsoft", product),)), version, device.os_name, is_os=True)
    identity = {Platform.MACOS: MACOS, Platform.IOS: IPADOS if device.os_name.lower().startswith("ipados") else IOS}.get(device.platform)
    return InstalledSoftware(identity, version, device.os_name, is_os=True) if identity else None


@dataclass(frozen=True)
class KnownVulnerability:
    record: CveRecord
    match: CpeMatch
    kev: KevEntry | None = None

    @property
    def cve_id(self) -> str:
        return self.record.cve_id

    @property
    def urgency(self) -> tuple:
        """Sort key, most urgent first: exploited, then CVSS, then newest."""
        return (self.kev is None, -(self.record.cvss or 0.0), _negated_id(self.cve_id))


@dataclass(frozen=True)
class SoftwareVulnerabilities:
    software: InstalledSoftware
    vulnerabilities: tuple[KnownVulnerability, ...]  # most urgent first

    @property
    def exploited(self) -> list[KnownVulnerability]:
        return [v for v in self.vulnerabilities if v.kev is not None]

    @property
    def highest_cvss(self) -> float | None:
        scores = [v.record.cvss for v in self.vulnerabilities if v.record.cvss is not None]
        return max(scores) if scores else None

    @property
    def fixed_in(self) -> str | None:
        """The version fixing every listed CVE, when NVD gives each fix
        ("versionEndExcluding"); None when one of them is not bounded so."""
        fixes = [v.match.versions.end_excluding for v in self.vulnerabilities]
        if not fixes or any(fix is None or parse_version(fix) is None for fix in fixes):
            return None
        return max(fixes, key=parse_version)


class VulnerabilityIndex:
    """CVEs of the fleet's software, read from the catalog once per audit."""

    def __init__(self, catalog: CveCatalog, kev: KevCatalog) -> None:
        self._catalog = catalog
        self._kev = kev
        self._cache: dict[tuple[SoftwareIdentity, str], tuple[KnownVulnerability, ...]] = {}

    @classmethod
    def empty(cls) -> VulnerabilityIndex:
        return cls(InMemoryCveCatalog([]), InMemoryKevCatalog())

    @classmethod
    def build(cls, devices: Iterable[Device], cves: CveCatalog, kev: KevCatalog) -> VulnerabilityIndex:
        """One catalog query for every product of the fleet, then in memory."""
        keys = {key for device in devices for software in installed_software(device) for key in software.identity.product_keys}
        return cls(InMemoryCveCatalog(cves.records_for(keys)) if keys else InMemoryCveCatalog([]), kev)

    def for_device(self, device: Device) -> list[SoftwareVulnerabilities]:
        found = []
        for software in installed_software(device):
            vulnerabilities = self._vulnerabilities(software)
            if vulnerabilities:
                found.append(SoftwareVulnerabilities(software, vulnerabilities))
        return found

    def _vulnerabilities(self, software: InstalledSoftware) -> tuple[KnownVulnerability, ...]:
        # 300 devices mostly share a handful of versions: match each once.
        key = (software.identity, software.version)
        if key not in self._cache:
            self._cache[key] = self._match(software)
        return self._cache[key]

    def _match(self, software: InstalledSoftware) -> tuple[KnownVulnerability, ...]:
        by_cve: dict[str, KnownVulnerability] = {}
        for hit in find_vulnerabilities(self._catalog, software.identity.candidates(software.version)):
            if _names_a_version(hit.match) and hit.record.cve_id not in by_cve:
                by_cve[hit.record.cve_id] = KnownVulnerability(hit.record, hit.match, self._kev.get(hit.record.cve_id))
        return tuple(sorted(by_cve.values(), key=lambda v: v.urgency))


def _names_a_version(match: CpeMatch) -> bool:
    """NVD entries such as "cpe:2.3:a:microsoft:365_apps:-" affect "every
    version": they cannot tell a patched device from a vulnerable one."""
    return not (match.versions.is_unbounded and match.cpe.version in (ANY, "-"))


def _negated_id(cve_id: str) -> tuple[int, int]:
    """CVE-2025-1234 sorts before CVE-2024-9999 (newest first)."""
    parts = cve_id.split("-")
    try:
        return -int(parts[1]), -int(parts[2])
    except (IndexError, ValueError):
        return 0, 0


def summarize(vulnerabilities: Sequence[KnownVulnerability], limit: int) -> list[str]:
    lines = []
    for vulnerability in vulnerabilities[:limit]:
        record = vulnerability.record
        score = f"CVSS {record.cvss:.1f}" if record.cvss is not None else "not scored yet"
        exploited = ", actively exploited (CISA KEV)" if vulnerability.kev else ""
        summary = " ".join(record.summary.split())
        lines.append(f"- {record.cve_id} ({score}{exploited}): {summary[:200]}{'…' if len(summary) > 200 else ''}")
    if len(vulnerabilities) > limit:
        lines.append(f"- … and {len(vulnerabilities) - limit} more")
    return lines
