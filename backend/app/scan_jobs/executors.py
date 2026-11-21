"""
Scan executors — one strategy per scan type.

Network scans (internal / external) run the plugin engine against a target
and need a profile. API and IaC scans are driven by an uploaded document
stored in the job's metadata and need no profile.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from app.scan_jobs.repository import ScanJobSnapshot
from app.scanner.engine import ProgressCallback, ScanEngine
from app.scanner.plugins.base import Finding
from app.scanner.profile import ScanProfile
from app.scanner.target import ScanType


class ScanExecutor(Protocol):
    requires_profile: bool

    async def execute(self, job: ScanJobSnapshot, profile: ScanProfile, progress: ProgressCallback) -> list[Finding]: ...


class StandaloneScanner(Protocol):
    async def run_standalone(self, config: dict[str, Any], progress_callback: ProgressCallback | None = None) -> list[Finding]: ...


class EngineScanExecutor:
    requires_profile = True

    def __init__(self, engine_factory: Callable[[], ScanEngine]) -> None:
        self._engine_factory = engine_factory

    async def execute(self, job: ScanJobSnapshot, profile: ScanProfile, progress: ProgressCallback) -> list[Finding]:
        return await self._engine_factory().scan(
            job.target,
            profile,
            job.workspace_id,
            ScanType.parse(job.scan_type),
            progress_callback=progress,
            job_id=job.id,
        )


class StandaloneScanExecutor:
    requires_profile = False

    def __init__(self, config_key: str, scanner_factory: Callable[[], StandaloneScanner]) -> None:
        self._config_key = config_key
        self._scanner_factory = scanner_factory

    async def execute(self, job: ScanJobSnapshot, profile: ScanProfile, progress: ProgressCallback) -> list[Finding]:
        return await self._scanner_factory().run_standalone(job.scanner_config(self._config_key), progress_callback=progress)


def _api_scanner() -> StandaloneScanner:
    from app.scanner.plugins import api_scanner

    return api_scanner.Check(api_scanner.META)


def _iac_scanner() -> StandaloneScanner:
    from app.scanner.plugins import iac_scanner

    return iac_scanner.Check()


def default_executors(engine_factory: Callable[[], ScanEngine]) -> dict[ScanType, ScanExecutor]:
    network = EngineScanExecutor(engine_factory)
    return {
        ScanType.INTERNAL: network,
        ScanType.EXTERNAL: network,
        ScanType.API: StandaloneScanExecutor("api_scanner_config", _api_scanner),
        ScanType.IAC: StandaloneScanExecutor("iac_scanner_config", _iac_scanner),
    }
