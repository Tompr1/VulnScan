"""
Scan engine — runs the plugins enabled by a profile against one target.

The engine receives every collaborator it needs (plugin registry, allowlist,
time budget, cancellation signal, clock). Production wiring lives in
:func:`default_engine`; tests build an engine from fakes.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from enum import StrEnum

from app.core.config import settings
from app.scanner.allowlist import AllowlistPolicy, AllowlistSource
from app.scanner.budget import ScanBudget
from app.scanner.cancellation import CancellationSignal, NeverCancelled, RedisCancellationSignal
from app.scanner.context import ScanContext, ScanPolicy, stable_fingerprint
from app.scanner.plugins.base import Finding, Plugin
from app.scanner.plugins.loader import PluginRegistry, builtin_registry
from app.scanner.profile import ScanProfile
from app.scanner.remediation import enrich_description, enrich_remediation
from app.scanner.resources import ScanResources, ScanResourcesFactory
from app.scanner.target import ScanTarget, ScanType

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int, str, str, str], Awaitable[None] | None]


class PluginStatus(StrEnum):
    RUNNING = "running"
    DONE = "done"
    TIMEOUT = "timeout"
    ERROR = "error"


class ScanEngine:
    def __init__(
        self,
        registry: PluginRegistry,
        allowlist: AllowlistSource,
        budget: ScanBudget,
        request_timeout_seconds: float,
        cancellation: CancellationSignal | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        resources: ScanResourcesFactory | None = None,
    ) -> None:
        self._registry = registry
        self._allowlist = allowlist
        self._budget = budget
        self._request_timeout_seconds = request_timeout_seconds
        self._cancellation = cancellation or NeverCancelled()
        self._monotonic = monotonic
        self._resources = resources or (lambda _workspace_id: ScanResources.none())

    async def scan(
        self,
        target: str,
        profile: ScanProfile,
        workspace_id: int,
        scan_type: ScanType = ScanType.INTERNAL,
        progress_callback: ProgressCallback | None = None,
        job_id: int | None = None,
    ) -> list[Finding]:
        """Run the profile's plugins and return deduplicated, enriched findings.

        Raises :class:`app.scanner.target.InvalidTargetError` for a target
        without a host.
        """
        scan_target = ScanTarget.parse(target)
        allowlist = self._allowlist.policy_for(workspace_id)
        if not allowlist.allows(scan_target, scan_type):
            return [_allowlist_blocked_finding(scan_target, allowlist)]

        run = _ScanRun(
            registry=self._registry,
            budget=self._budget,
            cancellation=self._cancellation,
            monotonic=self._monotonic,
            target=scan_target,
            scan_type=scan_type,
            plugin_ids=self._registry.resolve_enabled(profile.plugin_selection),
            context=self._new_context(scan_target, profile, workspace_id, scan_type),
            progress=_ProgressReporter(progress_callback),
            job_id=job_id,
        )
        findings = await run.execute()
        for finding in findings:
            enrich_remediation(finding)
            enrich_description(finding, scan_target.raw, scan_type)
        return findings

    def _new_context(
        self, target: ScanTarget, profile: ScanProfile, workspace_id: int, scan_type: ScanType
    ) -> ScanContext:
        ctx = ScanContext(
            policy=ScanPolicy(timeout_seconds=self._request_timeout_seconds),
            resources=self._resources(workspace_id),
        )
        ctx.set("workspace_id", workspace_id)
        ctx.set("target_raw", target.raw)
        ctx.set("target_host", target.host)
        ctx.set("target_scheme", target.scheme)
        ctx.set("scan_type", scan_type.value)
        ctx.set("scan.started_at", datetime.now(timezone.utc).isoformat())
        ctx.set("profile_options", profile.options)
        return ctx


class _ScanRun:
    """State of one scan: the context shared by plugins and the findings so far."""

    def __init__(
        self,
        registry: PluginRegistry,
        budget: ScanBudget,
        cancellation: CancellationSignal,
        monotonic: Callable[[], float],
        target: ScanTarget,
        scan_type: ScanType,
        plugin_ids: list[str],
        context: ScanContext,
        progress: _ProgressReporter,
        job_id: int | None,
    ) -> None:
        self._registry = registry
        self._budget = budget
        self._cancellation = cancellation
        self._monotonic = monotonic
        self._target = target
        self._scan_type = scan_type
        self._plugin_ids = plugin_ids
        self._ctx = context
        self._progress = progress
        self._job_id = job_id
        self._started = monotonic()
        self._findings: list[Finding] = []

    @property
    def _total(self) -> int:
        return len(self._plugin_ids)

    def _elapsed(self) -> float:
        return self._monotonic() - self._started

    async def execute(self) -> list[Finding]:
        for step, plugin_id in enumerate(self._plugin_ids):
            if self._cancel_requested():
                self._findings.append(self._cancelled_finding(step))
                logger.info("Scan cancelled by user (job #%s) at plugin %d/%d", self._job_id, step, self._total)
                break
            elapsed = self._elapsed()
            if self._budget.is_exhausted(elapsed):
                await self._skip_remaining(step, elapsed)
                break
            await self._run_plugin(step, self._registry.get(plugin_id), elapsed)
        return self._findings

    def _cancel_requested(self) -> bool:
        return self._job_id is not None and self._cancellation.consume(self._job_id)

    async def _run_plugin(self, step: int, plugin: Plugin, elapsed: float) -> None:
        meta = plugin.meta
        await self._progress(step, self._total, meta.plugin_id, meta.name, PluginStatus.RUNNING)

        timeout = self._budget.plugin_timeout(meta.timeout_seconds, self._scan_type, elapsed)
        # Plugins read this to keep their own request timeouts below the kill limit.
        self._ctx.set("_effective_timeout", timeout)
        try:
            result = await asyncio.wait_for(
                plugin.run(self._target.host, self._ctx),
                timeout=self._budget.kill_timeout(timeout),
            )
        except TimeoutError:
            evidence = (
                f"plugin_timeout={meta.timeout_seconds}s effective_timeout={timeout:.1f}s "
                f"budget_remaining={self._budget.remaining(elapsed):.1f}s "
                f"scan_timeout_seconds={self._ctx.policy.timeout_seconds}"
            )
            await self._record_failure(step, plugin, self._timeout_finding(plugin, evidence), PluginStatus.TIMEOUT)
            return
        except Exception as exc:  # a crashing plugin must never abort the whole scan
            logger.warning("Plugin %s failed: %s", meta.plugin_id, exc)
            await self._record_failure(step, plugin, self._error_finding(plugin, exc), PluginStatus.ERROR)
            return

        for key, value in (result.artifacts or {}).items():
            self._ctx.set(key, value)
        for finding in result.findings or []:
            self._add_finding(finding)
        await self._progress(step, self._total, meta.plugin_id, meta.name, PluginStatus.DONE)

    def _add_finding(self, finding: Finding) -> None:
        if not finding.fingerprint:
            finding.fingerprint = stable_fingerprint(self._target.raw, finding.plugin_id, finding.title)
        if self._ctx.dedup(finding.fingerprint):
            self._findings.append(finding)

    async def _record_failure(self, step: int, plugin: Plugin, finding: Finding, status: PluginStatus) -> None:
        self._findings.append(finding)
        # Downstream plugins read these keys: give them empty values to work with.
        for key, value in plugin.meta.fallback_artifacts().items():
            if not self._ctx.has(key):
                self._ctx.set(key, value)
        await self._progress(step, self._total, plugin.meta.plugin_id, plugin.meta.name, status)

    async def _skip_remaining(self, step: int, elapsed: float) -> None:
        skipped = self._plugin_ids[step:]
        remaining = self._budget.remaining(elapsed)
        for plugin_id in skipped:
            self._findings.append(self._budget_skip_finding(self._registry.get(plugin_id), elapsed, remaining, len(skipped)))
        await self._progress(self._total - 1, self._total, "budget", f"Budget exhausted ({len(skipped)} skipped)", PluginStatus.DONE)
        logger.warning("Scan budget exhausted after %.1fs — skipped %d plugins: %s", elapsed, len(skipped), skipped)

    # ── Synthetic findings ────────────────────────────────────────────────

    def _system_finding(self, plugin_id: str, title: str, evidence: str, remediation: str, *salt: str) -> Finding:
        return Finding(
            severity="info",
            plugin_id=plugin_id,
            title=title,
            evidence=evidence,
            remediation=remediation,
            affected=self._target.raw,
            fingerprint=stable_fingerprint(self._target.raw, plugin_id, *salt),
        )

    def _cancelled_finding(self, step: int) -> Finding:
        return self._system_finding(
            "system.cancelled",
            f"Scan cancelled by user after {step}/{self._total} plugins",
            f"cancelled_at_step={step} total_plugins={self._total} elapsed={self._elapsed():.1f}s",
            "Scan was manually cancelled. Re-run with the same profile to complete all plugins.",
            str(self._job_id),
        )

    def _budget_skip_finding(self, plugin: Plugin, elapsed: float, remaining: float, skipped: int) -> Finding:
        return self._system_finding(
            plugin.meta.plugin_id,
            f"Plugin skipped (scan budget exhausted): {plugin.meta.name}",
            f"elapsed={elapsed:.1f}s budget={self._budget.total_seconds}s "
            f"remaining={remaining:.1f}s skipped_plugins={skipped}",
            "The global scan budget was exhausted before this plugin could run. "
            "Increase SCAN_BUDGET_SECONDS in .env, reduce the number of enabled "
            "plugins, or use a lighter scan profile.",
            "budget_skip",
        )

    def _timeout_finding(self, plugin: Plugin, evidence: str) -> Finding:
        return self._system_finding(
            plugin.meta.plugin_id,
            f"Plugin timed out: {plugin.meta.name}",
            evidence,
            "The plugin exceeded its execution budget. Increase this plugin's "
            "META.timeout_seconds in the plugin file, or disable the plugin "
            "for this profile if the target is not applicable.",
            "timeout",
        )

    def _error_finding(self, plugin: Plugin, exc: Exception) -> Finding:
        return self._system_finding(
            plugin.meta.plugin_id,
            f"Plugin error: {plugin.meta.name}",
            str(exc)[:512],
            f"The {plugin.meta.name} plugin encountered an error. "
            "Check target connectivity and plugin configuration.",
            "error",
        )


def _allowlist_blocked_finding(target: ScanTarget, allowlist: AllowlistPolicy) -> Finding:
    return Finding(
        severity="info",
        plugin_id="policy.allowlist",
        title="Target blocked by allowlist policy",
        description=(
            f"Target '{target.raw}' is not in this client's allowlist. "
            "A client admin can add it in Settings → Allowlist to permit scanning. "
            "Alternatively, use 'External / Web' scan type for public targets."
        ),
        remediation=(
            "To scan this target, either:\n"
            "1. Switch to 'External / Web' scan type for public targets\n"
            "2. Add the target to this client's allowlist in Settings → Allowlist\n"
            "   Example: 10.0.0.0/8,.example.com,target.com"
        ),
        evidence=f"Allowlist: {allowlist}",
        affected=target.raw,
        fingerprint=stable_fingerprint(target.raw, "allowlist"),
    )


class _ProgressReporter:
    """Calls the optional sync-or-async progress callback; a failing callback
    is logged and never interrupts the scan."""

    def __init__(self, callback: ProgressCallback | None) -> None:
        self._callback = callback

    async def __call__(self, step: int, total: int, plugin_id: str, name: str, status: PluginStatus) -> None:
        if self._callback is None:
            return
        try:
            result = self._callback(step, total, plugin_id, name, status.value)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:  # progress is cosmetic: never fail the scan on it
            logger.warning("Progress callback failed at %s/%s: %s", plugin_id, status, exc)


@functools.lru_cache(maxsize=1)
def default_engine() -> ScanEngine:
    """Engine wired with the built-in plugins and the application settings."""
    from app.db.session import SessionLocal
    from app.scanner.client_allowlists import SqlClientAllowlists
    from app.scanner.sql_resources import SqlScanResources

    return ScanEngine(
        registry=builtin_registry(),
        allowlist=SqlClientAllowlists(SessionLocal, platform_default=settings.ALLOWLIST),
        budget=ScanBudget(total_seconds=float(settings.SCAN_BUDGET_SECONDS)),
        request_timeout_seconds=float(settings.SCAN_TIMEOUT_SECONDS),
        cancellation=RedisCancellationSignal.from_url(settings.REDIS_URL),
        resources=SqlScanResources(SessionLocal),
    )
