"""
A probe went offline, or came back: the message sent to the client's
integrations (event "probe_status" of the notification preferences).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

EVENT = "probe_status"


def duration_text(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{max(minutes, 1)} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes:02d}"
    return f"{hours // 24} days"


@dataclass(frozen=True)
class ProbeStatusAlert:
    probe_id: int
    probe_name: str
    client_name: str
    online: bool
    # Offline: when it was last heard from. Back online: when it went offline.
    since: datetime
    at: datetime
    waiting_jobs: int = 0
    url: str | None = None

    @property
    def state(self) -> str:
        return "back online" if self.online else "OFFLINE"

    @property
    def subject(self) -> str:
        return f"v0cday: scan probe {self.probe_name} ({self.client_name}) is {self.state}"

    @property
    def lines(self) -> list[str]:
        elapsed = duration_text((self.at - self.since).total_seconds())
        if self.online:
            lines = [f"The probe is connected again after {elapsed} offline."]
        else:
            lines = [
                f"No contact for {elapsed}: scans routed to this probe wait, then fail.",
                "Check the VM in the client's network: powered on, network, outbound HTTPS to the platform.",
            ]
        if self.waiting_jobs:
            lines.append(f"{self.waiting_jobs} scan(s) waiting for it.")
        return lines

    def webhook_payload(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "probe": self.probe_name,
            "client": self.client_name,
            "online": self.online,
            "since": self.since.isoformat(),
            "at": self.at.isoformat(),
            "waiting_jobs": self.waiting_jobs,
            "url": self.url,
        }
