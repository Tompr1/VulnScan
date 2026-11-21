"""
Plugin contract for the VulnScan scanner framework.

A plugin module exposes a module-level ``META`` (:class:`PluginMeta`) and a
``Check`` class deriving from :class:`Plugin`. The registry instantiates
``Check(META)``; the engine only ever talks to the :class:`Plugin` interface.
"""
from __future__ import annotations

import copy
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

# Re-exported so plugins only need to import from base.
from app.scanner.context import ScanContext, ScanPolicy  # noqa: F401


@dataclass
class PluginMeta:
    plugin_id: str
    name: str
    category: str
    provides: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    enabled_by_default: bool = True
    timeout_seconds: float = 30.0
    # Soft dependencies affect execution ORDER (run after these plugins) but do
    # not auto-enable them. Used when the consumed data is optional.
    soft_depends_on: list[str] = field(default_factory=list)
    # Value published for a provided artifact when the plugin times out or
    # fails, so downstream plugins can still read it. Keys that are not listed
    # default to an empty list.
    artifact_defaults: dict[str, Any] = field(default_factory=dict)

    @property
    def ordering_dependencies(self) -> set[str]:
        """Plugins that must run before this one (hard and soft)."""
        return set(self.depends_on) | set(self.soft_depends_on)

    def fallback_artifacts(self) -> dict[str, Any]:
        """Fresh default values for every artifact this plugin provides."""
        return {key: copy.deepcopy(self.artifact_defaults.get(key, [])) for key in self.provides}


@dataclass
class Finding:
    plugin_id: str
    title: str
    severity: str = "info"
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    fingerprint: str = ""
    references: list[str] = field(default_factory=list)
    cvss: float | None = None
    cve: str | None = None
    is_kev: bool = False
    confidence: float = 1.0
    affected: str = ""


@dataclass
class PluginResult:
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


class Plugin(ABC):
    """Base class of every scanner check."""

    def __init__(self, meta: PluginMeta) -> None:
        self._meta = meta

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    @abstractmethod
    async def run(self, target: str, ctx: ScanContext) -> PluginResult:
        """Scan ``target`` and return findings plus published artifacts."""
