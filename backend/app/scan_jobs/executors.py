"""
Scan executors — one strategy per scan type.

Network scans (internal / external) run the plugin engine against a target
and need a profile. API and IaC scans are driven by an uploaded document
stored in the job's metadata, and inventory scans by a fleet manager
connection (Intune…); none of them needs a profile.

An executor runs an assignment (``app.scan_jobs.assignment``) and needs no
database of its own, except the inventory one, which collects through the
platform's fleet manager connections and so only runs on the platform.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, Protocol

from app.scan_jobs.assignment import INVENTORY_CONNECTION_KEY, ScanAssignment
from app.scanner.engine import ProgressCallback, ScanEngine
from app.scanner.plugins.base import Finding
from app.scanner.resources import ScanResources
from app.scanner.target import ScanType


class ScanExecutor(Protocol):
    # Whether the workspace's automatic AI analysis may run on the findings.
    ai_analysis: bool

    async def execute(
        self, assignment: ScanAssignment, resources: ScanResources, progress: ProgressCallback
    ) -> list[Finding]: ...


class StandaloneScanner(Protocol):
    async def run_standalone(self, config: dict[str, Any], progress_callback: ProgressCallback | None = None) -> list[Finding]: ...


class EngineScanExecutor:
    ai_analysis = True

    def __init__(self, engine_factory: Callable[[], ScanEngine]) -> None:
        self._engine_factory = engine_factory

    async def execute(
        self, assignment: ScanAssignment, resources: ScanResources, progress: ProgressCallback
    ) -> list[Finding]:
        return await self._engine_factory().scan(
            assignment.target,
            assignment.profile,
            assignment.workspace_id,
            ScanType.parse(assignment.scan_type),
            progress_callback=progress,
            job_id=assignment.job_id,
            resources=resources,
        )


class StandaloneScanExecutor:
    ai_analysis = True

    def __init__(self, config_key: str, scanner_factory: Callable[[], StandaloneScanner]) -> None:
        self._config_key = config_key
        self._scanner_factory = scanner_factory

    async def execute(
        self, assignment: ScanAssignment, resources: ScanResources, progress: ProgressCallback
    ) -> list[Finding]:
        return await self._scanner_factory().run_standalone(
            assignment.scanner_config(self._config_key), progress_callback=progress
        )


class InventoryCollector(Protocol):
    def collect(self, connection_id: int, workspace_id: int) -> Any: ...


class InventoryAuditor(Protocol):
    def run(self, connection_id: int, workspace_id: int, job_id: int) -> list[Finding]: ...


class InventoryScanExecutor:
    """Collects a fleet manager inventory (devices, apps, versions), stores
    it, then audits it (support, versions, known CVEs): the findings are the
    issues of each device."""

    # Inventory findings name users and devices, and validating outdated
    # software needs no AI: never send them to an AI provider automatically.
    ai_analysis = False
    COLLECT_ID = "inventory.collect"
    AUDIT_ID = "inventory.audit"

    def __init__(
        self,
        collector_factory: Callable[[], InventoryCollector],
        audit_factory: Callable[[], InventoryAuditor],
    ) -> None:
        self._collector_factory = collector_factory
        self._audit_factory = audit_factory

    async def execute(
        self, assignment: ScanAssignment, resources: ScanResources, progress: ProgressCallback
    ) -> list[Finding]:
        connection_id = assignment.meta.get(INVENTORY_CONNECTION_KEY)
        if not isinstance(connection_id, int):
            raise ValueError(f"inventory job #{assignment.job_id} does not name an inventory connection")
        # Graph and endoflife.date clients are synchronous: keep them off the event loop.
        await progress(0, 2, self.COLLECT_ID, "Device inventory", "running")
        await asyncio.to_thread(self._collector_factory().collect, connection_id, assignment.workspace_id)
        await progress(0, 2, self.COLLECT_ID, "Device inventory", "done")
        await progress(1, 2, self.AUDIT_ID, "OS and software audit", "running")
        findings = await asyncio.to_thread(
            self._audit_factory().run, connection_id, assignment.workspace_id, assignment.job_id
        )
        await progress(1, 2, self.AUDIT_ID, "OS and software audit", "done")
        return findings


def _api_scanner() -> StandaloneScanner:
    from app.scanner.plugins import api_scanner

    return api_scanner.Check(api_scanner.META)


def _iac_scanner() -> StandaloneScanner:
    from app.scanner.plugins import iac_scanner

    return iac_scanner.Check()


def default_executors(
    engine_factory: Callable[[], ScanEngine],
    inventory_collector_factory: Callable[[], InventoryCollector],
    inventory_audit_factory: Callable[[], InventoryAuditor],
) -> dict[ScanType, ScanExecutor]:
    network = EngineScanExecutor(engine_factory)
    return {
        ScanType.INTERNAL: network,
        ScanType.EXTERNAL: network,
        ScanType.API: StandaloneScanExecutor("api_scanner_config", _api_scanner),
        ScanType.IAC: StandaloneScanExecutor("iac_scanner_config", _iac_scanner),
        ScanType.INVENTORY: InventoryScanExecutor(inventory_collector_factory, inventory_audit_factory),
    }
