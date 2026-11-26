"""
Scan notifications — tells the workspace integrations (Slack, Teams, webhook,
e-mail) that a scan completed or failed, and alerts on new device issues
found by an inventory audit (app.inventory.alerts).

Each integration provider is a :class:`NotificationChannel`; supporting a new
provider means adding a channel, not editing the dispatch code.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from app.inventory.alerts import AlertItem, InventoryAlert
from app.probes.alerts import EVENT as PROBE_STATUS_EVENT
from app.probes.alerts import ProbeStatusAlert
from app.risk.severity import Severity
from app.scanner import notifier

logger = logging.getLogger(__name__)

TOP_FINDINGS_LIMIT = 10
ALERT_ITEMS_LIMIT = 20  # per message; the webhook gets them all
_SLACK_SECTION_CHARS = 2900  # Slack rejects section texts over 3000 characters
_SEVERITIES_BY_RISK = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


@dataclass(frozen=True)
class TopFinding:
    severity: Severity
    title: str


@dataclass(frozen=True)
class ScanSummary:
    job_id: int
    target: str
    scan_type: str
    saved_count: int
    severity_counts: Mapping[Severity, int]
    duration_seconds: int = 0
    top_findings: Sequence[TopFinding] = field(default_factory=tuple)
    has_kev: bool = False

    def count(self, severity: Severity) -> int:
        return self.severity_counts.get(severity, 0)

    @property
    def risk_level(self) -> str:
        """Highest severity present, e.g. ``CRITICAL``."""
        worst = next((s for s in _SEVERITIES_BY_RISK if self.count(s) > 0), Severity.INFO)
        return worst.value.upper()

    @property
    def duration_text(self) -> str:
        minutes, seconds = divmod(self.duration_seconds, 60)
        return f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

    @property
    def triggered_events(self) -> list[str]:
        events = ["scan_completed"]
        if self.count(Severity.CRITICAL) > 0:
            events.append("critical_finding")
        if self.has_kev:
            events.append("cisa_kev_match")
        return events

    @property
    def message(self) -> str:
        return (
            f"v0cday Job #{self.job_id} on {self.target} completed in {self.duration_text}. "
            f"Risk posture: {self.risk_level}. Findings: {self.saved_count} "
            f"({self.count(Severity.CRITICAL)} Critical, {self.count(Severity.HIGH)} High, "
            f"{self.count(Severity.MEDIUM)} Medium, {self.count(Severity.LOW)} Low, "
            f"{self.count(Severity.INFO)} Info)."
        )

    @property
    def top_findings_text(self) -> str:
        lines = [f"- [{f.severity.value.upper()}] {f.title[:90]}" for f in self.top_findings if f.title]
        return "\n".join(lines) or "- No findings recorded"

    def webhook_payload(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "status": "done",
            "findings_total": self.saved_count,
            "duration_seconds": self.duration_seconds,
            "risk_level": self.risk_level,
            "severities": {s.value: self.count(s) for s in Severity},
        }


@dataclass(frozen=True)
class ScanFailure:
    job_id: int
    target: str
    error: str
    error_type: str

    @property
    def message(self) -> str:
        return (
            f"v0cday Job #{self.job_id} on {self.target} FAILED. "
            f"Type: {self.error_type}. Error: {self.error[:200]}"
        )


class NotificationChannel(Protocol):
    def scan_completed(self, config: dict[str, Any], summary: ScanSummary) -> None: ...

    def scan_failed(self, config: dict[str, Any], failure: ScanFailure) -> None: ...

    def device_alert(self, config: dict[str, Any], alert: InventoryAlert) -> None: ...

    def probe_status(self, config: dict[str, Any], alert: ProbeStatusAlert) -> None: ...


class SlackChannel:
    def __init__(self, send: Callable[[dict, Any], Any] = notifier.send_slack_notification) -> None:
        self._send = send

    def scan_completed(self, config: dict[str, Any], summary: ScanSummary) -> None:
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": "v0cday Scan Completed", "emoji": True}},
            {
                "type": "section",
                "fields": [
                    _field("Target", f"`{summary.target}`"),
                    _field("Job", f"#{summary.job_id}"),
                    _field("Type", summary.scan_type.upper()),
                    _field("Duration", summary.duration_text),
                    _field("Findings", str(summary.saved_count)),
                    _field("Risk", summary.risk_level),
                ],
            },
            _text_section(
                "*Severity breakdown*\n"
                f"Critical: *{summary.count(Severity.CRITICAL)}* | High: *{summary.count(Severity.HIGH)}* | "
                f"Medium: *{summary.count(Severity.MEDIUM)}* | Low: *{summary.count(Severity.LOW)}* | "
                f"Info: *{summary.count(Severity.INFO)}*"
            ),
            _text_section(f"*Top findings*\n{summary.top_findings_text}"),
        ]
        if config.get("dashboard_url"):
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open Dashboard", "emoji": True},
                    "url": config["dashboard_url"],
                }],
            })
        text = (
            f"Scan complete: {summary.target} | Job #{summary.job_id} | "
            f"{summary.saved_count} findings | Risk {summary.risk_level}"
        )
        self._send(config, {"text": text, "blocks": blocks})

    def device_alert(self, config: dict[str, Any], alert: InventoryAlert) -> None:
        lines = [_slack_line(item) for item in alert.items[:ALERT_ITEMS_LIMIT]]
        if len(alert.items) > ALERT_ITEMS_LIMIT:
            lines.append(f"… and {len(alert.items) - ALERT_ITEMS_LIMIT} more")
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": _header(alert), "emoji": True}},
            *(_text_section(chunk) for chunk in _chunks(lines, _SLACK_SECTION_CHARS)),
            {"type": "context", "elements": [{"type": "mrkdwn", "text": _slack_escape(alert.footer)}]},
        ]
        if alert.devices_url:
            blocks.append({"type": "actions", "elements": [{
                "type": "button", "text": {"type": "plain_text", "text": "Open device inventory", "emoji": True},
                "url": alert.devices_url,
            }]})
        self._send(config, {"text": alert.subject, "blocks": blocks})

    def scan_failed(self, config: dict[str, Any], failure: ScanFailure) -> None:
        self._send(config, {
            "text": failure.message,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "v0cday Scan Failed"}},
                {"type": "section", "fields": [
                    _field("Target", f"`{failure.target}`"),
                    _field("Job", f"#{failure.job_id}"),
                    _field("Error type", failure.error_type),
                ]},
                _text_section(f"*Error*\n```{failure.error[:300]}```"),
            ],
        })

    def probe_status(self, config: dict[str, Any], alert: ProbeStatusAlert) -> None:
        blocks: list[dict[str, Any]] = [
            {"type": "header", "text": {"type": "plain_text", "text": alert.subject.removeprefix("v0cday: ")[:150]}},
            _text_section("\n".join(_slack_escape(line) for line in alert.lines)),
        ]
        if alert.url:
            blocks.append({"type": "actions", "elements": [{
                "type": "button", "text": {"type": "plain_text", "text": "Open scan probes"}, "url": alert.url,
            }]})
        self._send(config, {"text": alert.subject, "blocks": blocks})


class TeamsChannel:
    def __init__(self, send: Callable[[dict, Any], Any] = notifier.send_teams_notification) -> None:
        self._send = send

    def scan_completed(self, config: dict[str, Any], summary: ScanSummary) -> None:
        self._send(config, {
            "title": "v0cday Scan Completed",
            "text": summary.message,
            "Target": summary.target,
            "Job": f"#{summary.job_id}",
            "Type": summary.scan_type.upper(),
            "Duration": summary.duration_text,
            "Findings": str(summary.saved_count),
            "Risk": summary.risk_level,
            "Critical": str(summary.count(Severity.CRITICAL)),
            "High": str(summary.count(Severity.HIGH)),
            "Medium": str(summary.count(Severity.MEDIUM)),
            "Low": str(summary.count(Severity.LOW)),
        })

    def device_alert(self, config: dict[str, Any], alert: InventoryAlert) -> None:
        lines = [_markdown_line(item) for item in alert.items[:ALERT_ITEMS_LIMIT]]
        if len(alert.items) > ALERT_ITEMS_LIMIT:
            lines.append(f"… and {len(alert.items) - ALERT_ITEMS_LIMIT} more")
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": _header(alert), "wrap": True},
            *({"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"} for line in lines),
            {"type": "TextBlock", "text": alert.footer, "wrap": True, "isSubtle": True, "size": "Small"},
        ]
        card: dict[str, Any] = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard", "version": "1.4", "body": body,
        }
        if alert.devices_url:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open device inventory", "url": alert.devices_url}]
        self._send(config, {
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
        })

    def scan_failed(self, config: dict[str, Any], failure: ScanFailure) -> None:
        self._send(config, {
            "title": "v0cday Scan Failed",
            "text": failure.message,
            "Target": failure.target,
            "Job": f"#{failure.job_id}",
            "Error type": failure.error_type,
            "Error": failure.error[:300],
        })

    def probe_status(self, config: dict[str, Any], alert: ProbeStatusAlert) -> None:
        self._send(config, {
            "title": alert.subject,
            "text": " ".join(alert.lines),
            "Probe": alert.probe_name,
            "Client": alert.client_name,
            "State": alert.state,
        })


class WebhookChannel:
    def __init__(self, send: Callable[[dict, dict], Any] = notifier.send_webhook_notification) -> None:
        self._send = send

    def scan_completed(self, config: dict[str, Any], summary: ScanSummary) -> None:
        self._send(config, {"event": "scan_done", "data": summary.webhook_payload()})

    def device_alert(self, config: dict[str, Any], alert: InventoryAlert) -> None:
        self._send(config, {"event": "inventory_alert", "data": {
            "job_id": alert.job_id,
            "target": alert.target,
            "baseline": alert.baseline,
            "resolved": alert.resolved,
            "open_issues": alert.open_issues,
            "issues": [
                {
                    "device_id": item.issue.device_id,
                    "device": item.device_name,
                    "rule": item.issue.rule,
                    "title": item.headline,
                    "severity": item.issue.severity,
                    "is_kev": item.issue.is_kev,
                    "fingerprint": item.issue.fingerprint,
                    "url": item.link,
                }
                for item in alert.items
            ],
        }})

    def scan_failed(self, config: dict[str, Any], failure: ScanFailure) -> None:
        self._send(config, {
            "event": "scan_failed",
            "data": {
                "job_id": failure.job_id,
                "target": failure.target,
                "status": "failed",
                "error": failure.error[:500],
                "error_type": failure.error_type,
            },
        })

    def probe_status(self, config: dict[str, Any], alert: ProbeStatusAlert) -> None:
        self._send(config, {"event": "probe_online" if alert.online else "probe_offline", "data": alert.webhook_payload()})


class EmailChannel:
    def __init__(self, send: Callable[[dict, str, str], Any] = notifier.send_email_notification) -> None:
        self._send = send

    def scan_completed(self, config: dict[str, Any], summary: ScanSummary) -> None:
        body = f"{summary.message}\n\nTop findings:\n{summary.top_findings_text}"
        self._send(config, f"Scan Complete: {summary.target}", body)

    def scan_failed(self, config: dict[str, Any], failure: ScanFailure) -> None:
        self._send(config, f"Scan Failed: {failure.target}", failure.message)

    def device_alert(self, config: dict[str, Any], alert: InventoryAlert) -> None:
        lines = [_text_line(item) for item in alert.items[:ALERT_ITEMS_LIMIT]]
        if len(alert.items) > ALERT_ITEMS_LIMIT:
            lines.append(f"… and {len(alert.items) - ALERT_ITEMS_LIMIT} more")
        body = "\n".join([*lines, "", alert.footer])
        if alert.devices_url:
            body += f"\n\nDevice inventory: {alert.devices_url}"
        self._send(config, alert.subject, body)

    def probe_status(self, config: dict[str, Any], alert: ProbeStatusAlert) -> None:
        body = "\n".join(alert.lines)
        if alert.url:
            body += f"\n\nScan probes: {alert.url}"
        self._send(config, alert.subject, body)


def default_channels() -> dict[str, NotificationChannel]:
    return {
        "slack": SlackChannel(),
        "teams": TeamsChannel(),
        "webhook": WebhookChannel(),
        "email": EmailChannel(),
    }


@dataclass(frozen=True)
class Integration:
    provider: str
    config: dict[str, Any]


class IntegrationSource(Protocol):
    def enabled_integrations(self, workspace_id: int) -> list[Integration]: ...

    def notification_preferences(self, workspace_id: int) -> dict[str, Any]: ...


PreferenceCheck = Callable[[dict, list[str], str], bool]


class ScanNotifier:
    """Sends scan events to every enabled integration whose preferences ask for them.

    Notifications are best effort: a failing integration is logged and never
    fails the scan job.
    """

    def __init__(
        self,
        source: IntegrationSource,
        channels: Mapping[str, NotificationChannel] | None = None,
        should_notify: PreferenceCheck = notifier.should_notify,
    ) -> None:
        self._source = source
        self._channels = channels if channels is not None else default_channels()
        self._should_notify = should_notify

    def scan_completed(self, workspace_id: int, summary: ScanSummary) -> None:
        self._dispatch(workspace_id, summary.triggered_events, lambda ch, cfg: ch.scan_completed(cfg, summary))

    def scan_failed(self, workspace_id: int, failure: ScanFailure) -> None:
        self._dispatch(workspace_id, ["scan_failed"], lambda ch, cfg: ch.scan_failed(cfg, failure))

    def probe_status(self, workspace_id: int, alert: ProbeStatusAlert) -> None:
        self._dispatch(workspace_id, [PROBE_STATUS_EVENT], lambda ch, cfg: ch.probe_status(cfg, alert))

    def device_alert(self, workspace_id: int, alert: InventoryAlert) -> None:
        """Each integration gets only the issues of the events it subscribed
        to (vulnerabilities, OS, software, KEV); none of them, no message."""
        try:
            integrations = self._source.enabled_integrations(workspace_id)
            preferences = self._source.notification_preferences(workspace_id) if integrations else {}
        except Exception as exc:  # notifications must never fail the job
            logger.warning("Could not load integrations of workspace %d: %s", workspace_id, exc)
            return
        for integration in integrations:
            channel = self._channels.get(integration.provider)
            if channel is None:
                continue
            items = [i for i in alert.items if self._should_notify(preferences, i.issue.events, integration.provider)]
            if not items:
                logger.info("Device alert skipped for %s (preferences)", integration.provider)
                continue
            try:
                channel.device_alert(integration.config, alert.only(items))
            except Exception as exc:  # one broken integration must not block the others
                logger.warning("Device alert via %s failed: %s", integration.provider, exc)

    def _dispatch(
        self, workspace_id: int, events: list[str], send: Callable[[NotificationChannel, dict[str, Any]], None]
    ) -> None:
        try:
            integrations = self._source.enabled_integrations(workspace_id)
            preferences = self._source.notification_preferences(workspace_id) if integrations else {}
        except Exception as exc:  # notifications must never fail the scan job
            logger.warning("Could not load integrations of workspace %d: %s", workspace_id, exc)
            return

        for integration in integrations:
            channel = self._channels.get(integration.provider)
            if channel is None:
                logger.debug("No notification channel for provider %s", integration.provider)
                continue
            if not self._should_notify(preferences, events, integration.provider):
                logger.info("Notification skipped for %s (preferences)", integration.provider)
                continue
            try:
                send(channel, integration.config)
            except Exception as exc:  # one broken integration must not block the others
                logger.warning("Notification via %s failed: %s", integration.provider, exc)


def _header(alert: InventoryAlert) -> str:
    return alert.subject.removeprefix("v0cday: ")[:150]  # Slack header limit


def _severity_tag(item: AlertItem) -> str:
    tag = item.issue.severity.upper()
    return f"{tag} · KEV" if item.issue.is_kev else tag


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _slack_line(item: AlertItem) -> str:
    device = _slack_escape(item.device_name)
    device = f"<{item.link}|{device}>" if item.link else f"*{device}*"
    return f"• *[{_severity_tag(item)}]* {device} — {_slack_escape(item.headline)}"


def _markdown_line(item: AlertItem) -> str:
    device = item.device_name.replace("[", "(").replace("]", ")")
    device = f"[{device}]({item.link})" if item.link else f"**{device}**"
    return f"**[{_severity_tag(item)}]** {device} — {item.headline}"


def _text_line(item: AlertItem) -> str:
    line = f"- [{_severity_tag(item)}] {item.device_name}: {item.headline}"
    return f"{line}\n  {item.link}" if item.link else line


def _chunks(lines: Sequence[str], limit: int) -> list[str]:
    """Lines joined into texts of at most ``limit`` characters."""
    chunks: list[str] = []
    for line in lines:
        line = line[:limit]
        if chunks and len(chunks[-1]) + 1 + len(line) <= limit:
            chunks[-1] += "\n" + line
        else:
            chunks.append(line)
    return chunks


def _field(label: str, value: str) -> dict[str, str]:
    return {"type": "mrkdwn", "text": f"*{label}*\n{value}"}


def _text_section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def build_summary(
    job_id: int,
    target: str,
    scan_type: str,
    findings: Sequence[Any],
    severity_counts: Mapping[Severity, int],
    created_at: datetime | None,
    finished_at: datetime,
) -> ScanSummary:
    """Summary of a finished scan. ``findings`` need ``severity``,
    ``title``, ``risk_score`` and ``is_kev`` attributes."""
    ranked = sorted(enumerate(findings), key=lambda item: (item[1].risk_score, item[0]), reverse=True)
    duration = int((finished_at - created_at).total_seconds()) if created_at else 0
    return ScanSummary(
        job_id=job_id,
        target=target,
        scan_type=scan_type,
        saved_count=len(findings),
        severity_counts=severity_counts,
        duration_seconds=max(0, duration),
        top_findings=tuple(TopFinding(f.severity, f.title) for _, f in ranked[:TOP_FINDINGS_LIMIT]),
        has_kev=any(f.is_kev for f in findings),
    )
