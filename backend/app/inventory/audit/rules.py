"""
Audit rules — one class per check, each turning a device into issues.

A rule only reads the device and the AuditContext (vendor lifecycle, fleet
baseline, policy, date): no I/O, so each is unit-tested on plain Device
objects. Adding a check is adding a class to ``default_rules()``.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Protocol

from app.inventory.audit.fleet import FleetBaseline, FleetVersion, app_family, newest_apps
from app.inventory.audit.lifecycle import (
    CatalogUnavailableError,
    SupportCatalog,
    SupportCycle,
    is_older,
    is_precise_enough,
)
from app.inventory.audit.products import InstalledRelease, identify_app, identify_os
from app.inventory.domain import Device, InstalledApp, Platform


@dataclass(frozen=True)
class AuditIssue:
    """One problem on one device. ``subject`` identifies it across audits
    (with the rule and the device), so it deliberately leaves out versions:
    Chrome going from one outdated version to another is the same issue."""

    rule: str
    subject: str
    title: str
    severity: str
    description: str
    remediation: str
    evidence: tuple[tuple[str, str], ...] = ()
    confidence: float = 1.0
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditPolicy:
    support_warning_days: int = 60  # warn before an OS loses support
    app_support_grace_days: int = 14  # Chrome / Firefox majors expire every few weeks
    android_patch_max_age_days: int = 90
    fleet_min_devices: int = 2

    def __post_init__(self) -> None:
        if min(self.support_warning_days, self.app_support_grace_days, self.android_patch_max_age_days) < 0:
            raise ValueError("audit policy durations cannot be negative")
        if self.fleet_min_devices < 1:
            raise ValueError("fleet_min_devices must be at least 1")


class LifecycleLookup:
    """Vendor lifecycle of a release, remembering which products could not be
    checked (endoflife.date unreachable) so the audit can say so."""

    def __init__(self, catalog: SupportCatalog) -> None:
        self._catalog = catalog
        self.unavailable: set[str] = set()

    def cycle_of(self, release: InstalledRelease) -> SupportCycle | None:
        try:
            cycles = self._catalog.cycles(release.product.slug)
        except CatalogUnavailableError:
            self.unavailable.add(release.product.slug)
            return None
        return release.cycle_in(cycles)


@dataclass
class AuditContext:
    today: date
    lifecycle: LifecycleLookup
    fleet: FleetBaseline
    policy: AuditPolicy = field(default_factory=AuditPolicy)


class DeviceRule(Protocol):
    def evaluate(self, device: Device, context: AuditContext) -> Iterable[AuditIssue]: ...


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


def default_rules() -> list[DeviceRule]:
    return [OsSupportRule(), OsUpdateRule(), AndroidPatchLevelRule(), AppSupportRule(), AppUpdateRule()]


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

