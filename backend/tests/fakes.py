"""
Test doubles shared by the test suite.

Vocabulary (Meszaros, xUnit Test Patterns):
- Stub  — returns canned answers (StubCvssEnricher, StubExecutor, StubIntegrationSource);
- Fake  — lightweight working implementation (InMemoryScanJobRepository, FakeClock);
- Spy   — records calls so the test can assert on them (SpyChannel, SpyJobQueue, ...).

They implement the production protocols, which is what makes them
substitutable (Liskov) without any patching.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.job_queue import QueueUnavailableError
from app.scan_jobs.notifications import Integration, ScanFailure, ScanSummary
from app.scan_jobs.processing import ProcessedFinding
from app.scan_jobs.repository import JobCompletion, JobFailure, ScanJobSnapshot
from app.scanner.context import ScanContext
from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.profile import ScanProfile


# ── Clock ─────────────────────────────────────────────────────────────────────

class FakeClock:
    """Monotonic clock and UTC clock that only move when told to."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start
        self.utc = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def monotonic(self) -> float:
        return self.now

    def utc_now(self) -> datetime:
        return self.utc

    def advance(self, seconds: float) -> None:
        self.now += seconds
        self.utc += timedelta(seconds=seconds)


# ── Plugins ───────────────────────────────────────────────────────────────────

def meta(plugin_id: str, **overrides: Any) -> PluginMeta:
    values: dict[str, Any] = {"plugin_id": plugin_id, "name": plugin_id.title(), "category": "test"}
    values.update(overrides)
    return PluginMeta(**values)


class FakePlugin(Plugin):
    """Configurable plugin that also records the targets it was run against."""

    def __init__(
        self,
        plugin_meta: PluginMeta,
        findings: list[Finding] | None = None,
        artifacts: dict[str, Any] | None = None,
        error: Exception | None = None,
        sleep_seconds: float = 0.0,
        on_run=None,
    ) -> None:
        super().__init__(plugin_meta)
        self._findings = findings or []
        self._artifacts = artifacts or {}
        self._error = error
        self._sleep_seconds = sleep_seconds
        self._on_run = on_run
        self.targets: list[str] = []
        self.contexts: list[ScanContext] = []

    async def run(self, target: str, ctx: ScanContext) -> PluginResult:
        self.targets.append(target)
        self.contexts.append(ctx)
        if self._on_run:
            self._on_run(ctx)
        if self._sleep_seconds:
            await asyncio.sleep(self._sleep_seconds)
        if self._error:
            raise self._error
        return PluginResult(findings=list(self._findings), artifacts=dict(self._artifacts))

    @property
    def was_run(self) -> bool:
        return bool(self.targets)


def finding(title: str = "Finding", **overrides: Any) -> Finding:
    values: dict[str, Any] = {"plugin_id": "test.plugin", "title": title, "fingerprint": f"fp-{title}"}
    values.update(overrides)
    return Finding(**values)


# ── Scan cancellation & job queue ─────────────────────────────────────────────

class SpyCancellationSignal:
    def __init__(self, cancelled_jobs: set[int] | None = None) -> None:
        self._cancelled = set(cancelled_jobs or ())
        self.requested: list[int] = []

    def request(self, job_id: int) -> None:
        self.requested.append(job_id)
        self._cancelled.add(job_id)

    def consume(self, job_id: int) -> bool:
        if job_id in self._cancelled:
            self._cancelled.discard(job_id)
            return True
        return False


class SpyJobQueue:
    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.scans: list[int] = []
        self.analyses: list[int] = []

    def enqueue_scan(self, job_id: int) -> None:
        self._check()
        self.scans.append(job_id)

    def enqueue_ai_analysis(self, analysis_id: int) -> None:
        self._check()
        self.analyses.append(analysis_id)

    def _check(self) -> None:
        if not self.available:
            raise QueueUnavailableError("redis down")


# ── Finding processing ────────────────────────────────────────────────────────

class StubCvssEnricher:
    def __init__(self, scores: dict[str, tuple[float | None, float]] | None = None, default_confidence: float = 0.9) -> None:
        self._scores = scores or {}
        self._default_confidence = default_confidence

    def enrich_finding_cvss(self, cve_id: str, current_cvss: float | None) -> tuple[float | None, float]:
        return self._scores.get(cve_id, (current_cvss, self._default_confidence))


def no_compliance(cve: str | None, plugin_id: str) -> list[str]:
    return []


# ── Notifications ─────────────────────────────────────────────────────────────

class StubIntegrationSource:
    def __init__(self, integrations: list[Integration] | None = None, preferences: dict | None = None, error: Exception | None = None) -> None:
        self._integrations = integrations or []
        self._preferences = preferences or {}
        self._error = error

    def enabled_integrations(self, workspace_id: int) -> list[Integration]:
        if self._error:
            raise self._error
        return list(self._integrations)

    def notification_preferences(self, workspace_id: int) -> dict:
        return self._preferences


class SpyChannel:
    def __init__(self, error: Exception | None = None) -> None:
        self.completed: list[tuple[dict, ScanSummary]] = []
        self.failed: list[tuple[dict, ScanFailure]] = []
        self.alerts: list[tuple[dict, Any]] = []
        self._error = error

    def scan_completed(self, config: dict, summary: ScanSummary) -> None:
        if self._error:
            raise self._error
        self.completed.append((config, summary))

    def scan_failed(self, config: dict, failure: ScanFailure) -> None:
        if self._error:
            raise self._error
        self.failed.append((config, failure))

    def device_alert(self, config: dict, alert: Any) -> None:
        if self._error:
            raise self._error
        self.alerts.append((config, alert))


class SpyNotifier:
    """Stands in for ScanNotifier in runner tests."""

    def __init__(self) -> None:
        self.completed: list[tuple[int, ScanSummary]] = []
        self.failed: list[tuple[int, ScanFailure]] = []
        self.alerts: list[tuple[int, Any]] = []

    def scan_completed(self, workspace_id: int, summary: ScanSummary) -> None:
        self.completed.append((workspace_id, summary))

    def scan_failed(self, workspace_id: int, failure: ScanFailure) -> None:
        self.failed.append((workspace_id, failure))

    def device_alert(self, workspace_id: int, alert: Any) -> None:
        self.alerts.append((workspace_id, alert))


# ── Scan job runner collaborators ─────────────────────────────────────────────

@dataclass
class StoredJob:
    snapshot: ScanJobSnapshot
    status: str = "queued"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    failure: JobFailure | None = None
    completion: JobCompletion | None = None
    progress: list[str] = field(default_factory=list)


class InMemoryScanJobRepository:
    """Fake ScanJobRepository backed by dictionaries."""

    def __init__(self) -> None:
        self.jobs: dict[int, StoredJob] = {}
        self.profiles: dict[tuple[int, int], ScanProfile] = {}
        self.suppressed: dict[int, set[str]] = {}
        self.saved: dict[int, list[ProcessedFinding]] = {}
        self.deleted_credentials_for: list[int] = []
        self.fail_on_mark_failed = False

    def add_job(self, snapshot: ScanJobSnapshot) -> None:
        self.jobs[snapshot.id] = StoredJob(snapshot)

    def add_profile(self, workspace_id: int, profile_id: int, profile: ScanProfile) -> None:
        self.profiles[(workspace_id, profile_id)] = profile

    def status_of(self, job_id: int) -> str:
        return self.jobs[job_id].status

    def load_job(self, job_id: int) -> ScanJobSnapshot | None:
        stored = self.jobs.get(job_id)
        return stored.snapshot if stored else None

    def load_profile(self, workspace_id: int, profile_id: int | None) -> ScanProfile | None:
        return self.profiles.get((workspace_id, profile_id)) if profile_id is not None else None

    def mark_running(self, job_id: int, at: datetime) -> None:
        self.jobs[job_id].status, self.jobs[job_id].started_at = "running", at

    def mark_failed(self, job_id: int, failure: JobFailure, at: datetime) -> None:
        if self.fail_on_mark_failed:
            raise RuntimeError("database unavailable")
        stored = self.jobs[job_id]
        stored.status, stored.failure, stored.finished_at = "failed", failure, at

    def mark_done(self, job_id: int, completion: JobCompletion, at: datetime) -> None:
        stored = self.jobs[job_id]
        stored.status, stored.completion, stored.finished_at = "done", completion, at

    def mark_analyzing(self, job_id: int) -> None:
        self.jobs[job_id].status = "analyzing"

    def write_progress(self, job_id: int, progress_json: str) -> None:
        self.jobs[job_id].progress.append(progress_json)

    def suppressed_fingerprints(self, workspace_id: int) -> set[str]:
        return self.suppressed.get(workspace_id, set())

    def compliance_rows(self) -> list[dict]:
        return []

    def save_findings(self, job: ScanJobSnapshot, findings: list[ProcessedFinding]) -> None:
        self.saved.setdefault(job.id, []).extend(findings)

    def delete_ephemeral_credential(self, job: ScanJobSnapshot) -> None:
        self.deleted_credentials_for.append(job.id)


class StubExecutor:
    def __init__(
        self,
        findings: list[Finding] | None = None,
        error: Exception | None = None,
        requires_profile: bool = True,
        ai_analysis: bool = True,
    ) -> None:
        self.requires_profile = requires_profile
        self.ai_analysis = ai_analysis
        self._findings = findings or []
        self._error = error
        self.received_profiles: list[ScanProfile] = []

    async def execute(self, job: ScanJobSnapshot, profile: ScanProfile, progress) -> list[Finding]:
        self.received_profiles.append(profile)
        await progress(0, 1, "stub", "Stub", "running")
        if self._error:
            raise self._error
        await progress(0, 1, "stub", "Stub", "done")
        return list(self._findings)


class SpyGraph:
    def __init__(self) -> None:
        self.recorded: list[ProcessedFinding] = []
        self.closed = False

    def record(self, workspace_id: int, target: str, finding: ProcessedFinding) -> None:
        self.recorded.append(finding)

    def close(self) -> None:
        self.closed = True


class StubAiTrigger:
    def __init__(self, queues: bool = False, error: Exception | None = None) -> None:
        self._queues = queues
        self._error = error
        self.calls: list[tuple[int, int, int]] = []

    def maybe_queue(self, job_id: int, workspace_id: int, saved_findings: int) -> bool:
        self.calls.append((job_id, workspace_id, saved_findings))
        if self._error:
            raise self._error
        return self._queues
