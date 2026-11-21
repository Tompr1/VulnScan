"""
Audit rules — one class per check, each turning a device into issues.

A rule only reads the device and the AuditContext (vendor lifecycle, fleet
baseline, policy, date): no I/O, so each is unit-tested on plain Device
objects. Adding a check is adding a class to ``default_rules()``.
"""
from __future__ import annotations

from datetime import date

from app.inventory.audit.base import AuditContext, AuditIssue, DeviceRule
from app.inventory.audit.cves import SoftwareVulnerabilities, summarize
from app.inventory.audit.fleet import FleetVersion, app_family, newest_apps
from app.inventory.audit.lifecycle import SupportCycle, is_older, is_precise_enough
from app.inventory.audit.products import InstalledRelease, identify_app, identify_os
from app.inventory.domain import Device, InstalledApp, Platform
from app.risk.severity import Severity


# ── Operating system ──────────────────────────────────────────────────────────

class OsSupportRule:
    """OS release out of security support, or about to be."""

    def evaluate(self, device: Device, context: AuditContext) -> list[AuditIssue]:
        release = identify_os(device)
        cycle = context.lifecycle.cycle_of(release) if release else None
        if release is None or cycle is None:
            return []
        os_label = f"{release.product.title} {cycle.label}"
        evidence = (("OS", f"{release.product.title} {release.version}"), ("Release", os_label), _support_end(cycle))
        references = (release.product.reference_url,)
        if cycle.is_unsupported(context.today):
            return [AuditIssue(
                rule="os_unsupported",
                subject=f"{release.product.slug}:{cycle.name}",
                title=f"{os_label} is no longer supported",
                severity="high",
                description=_with_note(
                    f"{os_label} no longer receives security updates: vulnerabilities found since "
                    f"{_end_text(cycle)} will never be fixed on this device.", release),
                remediation=f"Upgrade the device to a supported {release.product.title} release, or replace it if the hardware cannot run one.",
                evidence=evidence,
                references=references,
            )]
        days_left = cycle.days_left(context.today)
        if days_left is not None and days_left <= context.policy.support_warning_days:
            return [AuditIssue(
                rule="os_support_ending",
                subject=f"{release.product.slug}:{cycle.name}",
                title=f"{os_label} support ends in {days_left} days",
                severity="low",
                description=_with_note(
                    f"{os_label} stops receiving security updates on {cycle.support_ends_on.isoformat()}.", release),
                remediation=f"Plan the upgrade to a newer {release.product.title} release before that date.",
                evidence=evidence,
                references=references,
            )]
        return []


class OsUpdateRule:
    """Supported OS release, but not its latest update: the vendor's latest
    release of the line when known precisely, otherwise the newest one
    deployed in the fleet (the case of Windows monthly updates)."""

    def evaluate(self, device: Device, context: AuditContext) -> list[AuditIssue]:
        release = identify_os(device)
        if release is None:
            return []
        cycle = context.lifecycle.cycle_of(release)
        if cycle is not None and cycle.is_unsupported(context.today):
            return []  # updating within a dead release does not help: OsSupportRule reports it
        reference = _reference(release.version, cycle, context.fleet.newest_os(device))
        if reference is None:
            return []
        latest, source, confidence = reference
        title = release.product.title
        return [AuditIssue(
            rule="os_outdated",
            subject=release.product.slug,
            title=f"{title} is not up to date ({release.version}, {latest} available)",
            severity="medium",
            description=f"The device runs {title} {release.version}; {latest} is {source}. "
                        "OS updates are where most security fixes ship.",
            remediation=f"Install the pending {title} updates, then check that the device syncs with Intune.",
            evidence=(("OS", f"{title} {release.version}"), ("Reference", f"{latest} ({source})")),
            confidence=confidence,
            references=(release.product.reference_url,),
        )]


class AndroidPatchLevelRule:
    """Android devices whose security patch level is too old."""

    def evaluate(self, device: Device, context: AuditContext) -> list[AuditIssue]:
        if device.platform is not Platform.ANDROID:
            return []
        patched_on = _date(device.security_patch_level)
        if patched_on is None:
            return []
        age = (context.today - patched_on).days
        if age <= context.policy.android_patch_max_age_days:
            return []
        return [AuditIssue(
            rule="android_patch_outdated",
            subject="android-security-patch",
            title=f"Android security patch level is {age} days old",
            severity="medium",
            description=f"The latest Android security patch installed is from {patched_on.isoformat()}. "
                        "Google publishes security patches every month.",
            remediation="Install the pending system updates; if the manufacturer no longer ships them, plan the replacement of the device.",
            evidence=(("Security patch level", patched_on.isoformat()), ("Age", f"{age} days")),
            references=("https://source.android.com/docs/security/bulletin",),
        )]


# ── Installed software ────────────────────────────────────────────────────────

class AppSupportRule:
    """Software on a release line its vendor no longer supports."""

    def evaluate(self, device: Device, context: AuditContext) -> list[AuditIssue]:
        issues = []
        for app in newest_apps(device.apps):
            release = identify_app(app)
            cycle = context.lifecycle.cycle_of(release) if release else None
            if release is None or cycle is None or not cycle.is_unsupported(context.today, context.policy.app_support_grace_days):
                continue
            label = f"{release.product.title} {cycle.label}"
            issues.append(AuditIssue(
                rule="app_unsupported",
                subject=f"{release.product.slug}:{cycle.name}",
                title=f"{label} is no longer supported",
                severity="medium",
                description=f"{app.name} {app.version} belongs to {label}, which no longer receives security "
                            f"updates since {_end_text(cycle)}.",
                remediation=f"Update {release.product.title} to a supported release, or uninstall it if it is no longer needed.",
                evidence=(("Application", f"{app.name} {app.version}"), ("Release", label), _support_end(cycle)),
                references=(release.product.reference_url,),
            ))
        return issues


class AppUpdateRule:
    """Software behind its latest release: the vendor's when known
    (endoflife.date), otherwise the newest deployed in the fleet."""

    def evaluate(self, device: Device, context: AuditContext) -> list[AuditIssue]:
        issues = []
        for app in newest_apps(device.apps):
            release = identify_app(app)
            cycle = context.lifecycle.cycle_of(release) if release else None
            if cycle is not None and cycle.is_unsupported(context.today, context.policy.app_support_grace_days):
                continue  # AppSupportRule reports it
            reference = _reference(app.version, cycle, context.fleet.newest_app(app))
            if reference is None:
                continue
            latest, source, confidence = reference
            issues.append(_outdated_app(app, latest, source, confidence, release))
        return issues


# ── Known vulnerabilities ─────────────────────────────────────────────────────

class VulnerableSoftwareRule:
    """Known CVEs on the OS build or an installed application. One issue per
    vulnerable product, listing its CVEs: the fix is one update, and 300
    devices behind on Windows would otherwise mean tens of thousands of
    findings a day."""

    MAX_LISTED = 15

    def evaluate(self, device: Device, context: AuditContext) -> list[AuditIssue]:
        return [self._issue(found) for found in context.vulnerabilities.for_device(device)]

    def _issue(self, found: SoftwareVulnerabilities) -> AuditIssue:
        software, vulnerabilities, exploited = found.software, found.vulnerabilities, found.exploited
        title = software.identity.title
        count = len(vulnerabilities)
        headline = f"{title} {software.version} has {count} known {'vulnerability' if count == 1 else 'vulnerabilities'}"
        if exploited:
            headline += f", {len(exploited)} actively exploited"
        most_urgent = vulnerabilities[0]
        highest = found.highest_cvss
        installed = f"{title if software.is_os else software.name} {software.version}"
        return AuditIssue(
            rule="os_vulnerable" if software.is_os else "app_vulnerable",
            # A product that becomes actively exploited is a new issue (and a new alert).
            subject=software.identity.key + (":kev" if exploited else ""),
            title=headline,
            severity=_cve_severity(highest, bool(exploited)),
            description="\n".join([f"{installed} is affected by:", *summarize(vulnerabilities, self.MAX_LISTED)]),
            remediation=_cve_remediation(found),
            evidence=(
                ("Installed", installed),
                ("Known vulnerabilities", str(count)),
                ("Actively exploited (CISA KEV)", ", ".join(v.cve_id for v in exploited) or "none"),
                ("Highest CVSS", f"{highest:.1f}" if highest is not None else "not scored"),
                ("Fixed in", found.fixed_in or "see each CVE"),
            ),
            confidence=0.9,  # curated product identification, NVD version ranges
            references=tuple(f"https://nvd.nist.gov/vuln/detail/{v.cve_id}" for v in vulnerabilities[:5]),
            cve=most_urgent.cve_id,
            cvss=highest,
            is_kev=bool(exploited),
        )


def default_rules() -> list[DeviceRule]:
    return [
        OsSupportRule(), OsUpdateRule(), AndroidPatchLevelRule(), AppSupportRule(), AppUpdateRule(),
        VulnerableSoftwareRule(),
    ]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _reference(installed: str, cycle: SupportCycle | None, fleet: FleetVersion | None) -> tuple[str, str, float] | None:
    """(newer version, where it comes from, confidence), or None when the
    installed version is current. Option c: the vendor first, the fleet when
    the vendor's latest release is unknown or too coarse to compare."""
    if cycle is not None and is_precise_enough(cycle.latest, installed):
        if is_older(installed, cycle.latest):
            return cycle.latest, "the latest release published by the vendor", 1.0
        return None
    if fleet is not None and is_older(installed, fleet.version):
        return fleet.version, f"already installed on {fleet.devices} devices of the fleet", 0.8
    return None


def _outdated_app(app: InstalledApp, latest: str, source: str, confidence: float, release: InstalledRelease | None) -> AuditIssue:
    return AuditIssue(
        rule="app_outdated",
        subject=release.product.slug if release else app_family(app.name),
        title=f"{app.name} is not up to date ({app.version}, {latest} available)",
        severity="low",
        description=f"The device runs {app.name} {app.version}; {latest} is {source}.",
        remediation=f"Update {app.name}, ideally through an Intune app deployment so that every device follows.",
        evidence=(("Application", f"{app.name} {app.version}"), ("Reference", f"{latest} ({source})")),
        confidence=confidence,
        references=(release.product.reference_url,) if release else (),
    )


def _cve_severity(highest_cvss: float | None, exploited: bool) -> str:
    if exploited:
        return Severity.CRITICAL.value
    # NVD has not scored every recent CVE yet: keep those visible.
    return Severity.from_score(highest_cvss).value if highest_cvss is not None else Severity.MEDIUM.value


def _cve_remediation(found: SoftwareVulnerabilities) -> str:
    software, fixed_in = found.software, found.fixed_in
    if software.is_os and software.identity.title.startswith("Windows"):
        action = "Install the latest Windows cumulative update"
        action += f" (build {fixed_in} or later)." if fixed_in else "."
    elif fixed_in:
        action = f"Update {software.identity.title} to {fixed_in} or later."
    else:
        action = f"Update {software.identity.title} to its latest version (see each CVE for the fixed release)."
    exploited = found.exploited
    if not exploited:
        return action
    dues = sorted(v.kev.due_date for v in exploited if v.kev.due_date)
    verb = "is" if len(exploited) == 1 else "are"
    urgency = f"{len(exploited)} of these CVEs {verb} exploited by attackers (CISA KEV): patch first"
    urgency += f"; CISA remediation deadline {dues[0].isoformat()}." if dues else "."
    if any(v.kev.ransomware for v in exploited):
        urgency += " Used in ransomware campaigns."
    return f"{urgency}\n\n{action}"


def _support_end(cycle: SupportCycle) -> tuple[str, str]:
    return "End of support", _end_text(cycle)


def _end_text(cycle: SupportCycle) -> str:
    if cycle.support_ends_on is not None:
        return cycle.support_ends_on.isoformat()
    return "an unspecified date" if cycle.ended else "not announced"


def _with_note(text: str, release: InstalledRelease) -> str:
    return f"{text} {release.product.note}" if release.product.note else text


def _date(value: str | None) -> date | None:
    try:
        return date.fromisoformat((value or "").strip()[:10])
    except ValueError:
        return None

