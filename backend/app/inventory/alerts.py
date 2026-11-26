"""
Inventory alerts — tell the workspace about NEW device issues only.

After each audit, the issues that pass the workspace threshold (high and
critical by default, plus anything actively exploited) are compared with
those of the previous completed audit of the same connection, by
fingerprint. Only what is new is sent, in ONE message per audit grouping
every device, each with a link to its device page:
- an issue that stays open is not repeated the next day;
- an issue that worsens into the threshold, or whose product becomes
  actively exploited (its fingerprint changes, see VulnerableSoftwareRule),
  is new;
- the first audit of a connection sends a single baseline summary instead
  of hundreds of alerts.
The generic "scan completed" message is not sent for inventory jobs.
"""
from __future__ import annotations

import logging
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.risk.severity import Severity

logger = logging.getLogger(__name__)

PLUGIN_PREFIX = "inventory."
VULNERABILITY_EVENT = "device_vulnerability"
OS_EVENT = "device_os_issue"
SOFTWARE_EVENT = "device_software_issue"
KEV_EVENT = "cisa_kev_match"  # shared with network scans
_EVENT_BY_RULE = {
    "os_vulnerable": VULNERABILITY_EVENT,
    "app_vulnerable": VULNERABILITY_EVENT,
    "os_unsupported": OS_EVENT,
    "os_support_ending": OS_EVENT,
    "os_outdated": OS_EVENT,
    "android_patch_outdated": OS_EVENT,
    "app_unsupported": SOFTWARE_EVENT,
    "app_outdated": SOFTWARE_EVENT,
}
_SEVERITY_ORDER = list(Severity)  # most severe first


@dataclass(frozen=True)
class AlertSettings:
    """Workspace threshold: issues at least this severe, plus every actively
    exploited one when ``always_kev``."""

    min_severity: Severity = Severity.HIGH
    always_kev: bool = True

    @classmethod
    def from_stored(cls, stored: Mapping[str, Any]) -> AlertSettings:
        """Parse the stored workspace setting; invalid values keep their default."""
        default = cls()
        severity = Severity.parse(str(stored.get("min_severity") or "")) or default.min_severity
        always_kev = stored.get("always_kev")
        return cls(severity, always_kev if isinstance(always_kev, bool) else default.always_kev)

    def to_stored(self) -> dict[str, Any]:
        return {"min_severity": self.min_severity.value, "always_kev": self.always_kev}

    def passes(self, issue: KnownIssue) -> bool:
        if self.always_kev and issue.is_kev:
            return True
        severity = Severity.parse(issue.severity)
        return severity is not None and _SEVERITY_ORDER.index(severity) <= _SEVERITY_ORDER.index(self.min_severity)


@dataclass(frozen=True)
class KnownIssue:
    """A saved device finding, as far as alerting is concerned."""

    fingerprint: str
    plugin_id: str
    severity: str
    is_kev: bool = False
    device_id: int | None = None
    title: str = ""

    @classmethod
    def of(cls, finding: Any) -> KnownIssue:
        """From a saved finding (ProcessedFinding or row): needs fingerprint,
        plugin_id, severity, is_kev, device_id and title."""
        severity = finding.severity
        return cls(
            fingerprint=finding.fingerprint,
            plugin_id=finding.plugin_id,
            severity=getattr(severity, "value", severity),
            is_kev=bool(finding.is_kev),
            device_id=finding.device_id,
            title=finding.title,
        )

    @property
    def rule(self) -> str:
        return self.plugin_id.removeprefix(PLUGIN_PREFIX)

    @property
    def events(self) -> list[str]:
        """Notification preference events this issue belongs to."""
        event = _EVENT_BY_RULE.get(self.rule)
        if event is None:
            return []
        return [event, KEV_EVENT] if self.is_kev else [event]


@dataclass(frozen=True)
class AlertItem:
    issue: KnownIssue
    device_name: str
    link: str | None = None

    @property
    def headline(self) -> str:
        """The issue title without the " — <device>" suffix findings carry."""
        suffix = f" — {self.device_name}"
        title = self.issue.title
        return title[: -len(suffix)] if title.endswith(suffix) else title


@dataclass(frozen=True)
class InventoryAlert:
    job_id: int
    target: str  # the connection, e.g. "intune:Tenant de test"
    items: tuple[AlertItem, ...]  # most urgent first
    baseline: bool = False  # first audit: a summary of everything open
    resolved: int = 0
    open_issues: int = 0
    devices_url: str | None = None

    @property
    def exploited(self) -> int:
        return sum(item.issue.is_kev for item in self.items)

    @property
    def devices(self) -> int:
        return len({item.issue.device_id for item in self.items})

    def only(self, items: Sequence[AlertItem]) -> InventoryAlert:
        """The same alert restricted to some items (per channel preferences)."""
        return InventoryAlert(self.job_id, self.target, tuple(items), self.baseline, self.resolved,
                              self.open_issues, self.devices_url)

    @property
    def subject(self) -> str:
        count = len(self.items)
        if self.baseline:
            text = f"v0cday: first device audit of {self.target}, {count} open {_plural(count, 'issue')} on {self.devices} {_plural(self.devices, 'device')}"
        else:
            text = f"v0cday: {count} new device {_plural(count, 'issue')} on {self.devices} {_plural(self.devices, 'device')}"
        if self.exploited:
            text += f" ({self.exploited} actively exploited)"
        return text

    @property
    def footer(self) -> str:
        if self.baseline:
            return (f"Audit job #{self.job_id} of {self.target}. This is the starting point: "
                    "from now on, only new detections are alerted.")
        return (f"Audit job #{self.job_id} of {self.target}: {self.resolved} {_plural(self.resolved, 'issue')} "
                f"resolved since the previous audit, {self.open_issues} open in total.")


class AlertPolicy:
    def __init__(self, settings: AlertSettings) -> None:
        self._settings = settings

    def select(
        self, current: Sequence[KnownIssue], previous: Collection[KnownIssue] | None
    ) -> tuple[list[KnownIssue], bool, int]:
        """(issues to alert on, whether it is the baseline, resolved count).

        ``previous`` is None when the connection was never audited before.
        """
        alertable = [issue for issue in current if issue.device_id is not None and self._settings.passes(issue)]
        alertable.sort(key=_urgency)
        if previous is None:
            return alertable, True, 0
        already_alerted = {issue.fingerprint for issue in previous if self._settings.passes(issue)}
        still_there = {issue.fingerprint for issue in current}
        resolved = sum(1 for issue in previous if issue.device_id is not None and issue.fingerprint not in still_there)
        return [issue for issue in alertable if issue.fingerprint not in already_alerted], False, resolved


class DeviceLinks:
    """Deep links into the web UI (hash routes: no server rewrite needed).

    A link names its client (``#/c/<client id>/…``): an MSP technician who
    has several clients open lands on the right one, whichever was open last.
    """

    def __init__(self, base_url: str | None) -> None:
        self._base = (base_url or "").rstrip("/") or None

    def device(self, client_id: int, device_id: int | None) -> str | None:
        return f"{self._base}/#/c/{client_id}/inventory/devices/{device_id}" if self._base and device_id is not None else None

    def devices(self, client_id: int) -> str | None:
        return f"{self._base}/#/c/{client_id}/inventory" if self._base else None


class AlertHistory(Protocol):
    def previous_issues(self, job_id: int) -> list[KnownIssue] | None:
        """Issues of the completed audit preceding this job's, on the same
        connection — None when the connection was never audited before."""

    def device_names(self, device_ids: Collection[int]) -> dict[int, str]: ...

    def alert_settings(self, workspace_id: int) -> AlertSettings: ...


class DeviceAlertSender(Protocol):
    def device_alert(self, workspace_id: int, alert: InventoryAlert) -> None: ...


@dataclass
class InventoryAlerter:
    """Completion announcer of inventory jobs (replaces "scan completed")."""

    history: AlertHistory
    sender: DeviceAlertSender
    links: DeviceLinks = field(default_factory=lambda: DeviceLinks(None))

    def announce(self, job: Any, findings: Sequence[Any], summary: Any = None) -> InventoryAlert | None:
        """``findings`` are the job's saved findings (after suppression)."""
        current = [KnownIssue.of(finding) for finding in findings]
        previous = self.history.previous_issues(job.id)
        selected, baseline, resolved = AlertPolicy(self.history.alert_settings(job.workspace_id)).select(current, previous)
        if not selected:
            logger.info("Inventory job #%d: no new device issue to alert", job.id)
            return None
        names = self.history.device_names({issue.device_id for issue in selected})
        alert = InventoryAlert(
            job_id=job.id,
            target=job.target,
            items=tuple(
                AlertItem(issue, names.get(issue.device_id, f"device #{issue.device_id}"), self.links.device(job.workspace_id, issue.device_id))
                for issue in selected
            ),
            baseline=baseline,
            resolved=resolved,
            open_issues=sum(1 for issue in current if issue.device_id is not None),
            devices_url=self.links.devices(job.workspace_id),
        )
        self.sender.device_alert(job.workspace_id, alert)
        return alert


def _urgency(issue: KnownIssue) -> tuple:
    severity = Severity.parse(issue.severity)
    return (not issue.is_kev, _SEVERITY_ORDER.index(severity) if severity else len(_SEVERITY_ORDER), issue.title)


def _plural(count: int, word: str) -> str:
    return word if count == 1 else word + "s"
