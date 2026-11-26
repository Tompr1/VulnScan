"""
Plugin registry — discovers scanner plugins, orders them by dependency and
resolves which ones a profile enables.

The registry is a plain object built from a list of :class:`Plugin`
instances, so tests can build one from fakes without importing the 70
built-in plugin modules.
"""
from __future__ import annotations

import functools
import importlib
import logging
from collections import deque
from collections.abc import Iterable, Iterator, Mapping

from app.scanner.plugins.base import Plugin, PluginMeta

logger = logging.getLogger("v0cday.loader")

# Built-in plugin modules (relative to app.scanner.plugins). The list order is
# the tie-breaker of the topological sort, so it is kept explicit.
BUILTIN_PLUGIN_MODULES: tuple[str, ...] = (
    "port_scan",
    "nmap_portscan",
    "nmap_external",
    "http_fingerprint",
    "banner_grabber",
    "web_tech",
    "deep_fingerprint",
    "favicon_hash",
    "cpe_builder",
    "nvd_match",
    "cveorg_match",
    "endpoint_prober",
    "cms_match",
    "cisa_kev",
    "tls_basic",
    "ssh_inventory",
    "cve_packages",
    "local_security",
    "owasp_scanner",
    "cve_verifier",
    "dir_crawl",
    "file_inclusion",
    # Infrastructure
    "dns_enum",
    "db_auth_check",
    "ssh_audit",
    "smb_check",
    # Tier 1 security checks + MQTT
    "api_key_exposure",
    "jwt_scanner",
    "graphql_scanner",
    "security_headers",
    "mqtt_scanner",
    # Tier 2 — infrastructure & injection
    "snmp_community",
    "ftp_anon",
    "redis_noauth",
    "host_header_injection",
    "crlf_injection",
    "docker_api",
    "cloud_storage_misconfig",
    "waf_detection",
    "ssti_scanner",
    # Tier 3 — advanced recon, injection, cloud, API security
    "ssl_ct",
    "rate_limit_check",
    "open_redirect",
    "ldap_injection",
    "nosql_injection",
    "ssrf_deep",
    "websocket_check",
    "k8s_api",
    "unauth_api",
    # Tier 4 — deep injection testing
    "deep_sqli",
    "deep_cmdi",
    "advanced_xss",
    # Tier 5 — API-specific scanning (OpenAPI/Postman/GraphQL)
    "api_scanner",
    # Tier 6 — authenticated web scanning + UDP discovery (opt-in)
    "web_auth",
    "udp_portscan",
    # Tier 7 — passive recon & intelligence gathering
    "wayback_urls",
    "subdomain_takeover",
    "github_secret_scan",
    "dns_history",
    "cms_vuln_scanner",
    "ssl_grading",
    "sca_scanner",
    "screenshot_capture",
    # External tool integrations
    "subfinder_external",
    "httpx_external",
    "ffuf_external",
    "testssl_external",
    "nuclei_external",
    "sqlmap_external",
    # Tier 8 — CIS Benchmark auditing (opt-in, requires SSH)
    "cis_benchmark",
    "sca_server",
)

_PLUGIN_PACKAGE = "app.scanner.plugins"


class PluginRegistry:
    """Immutable collection of plugins indexed by ``plugin_id``."""

    def __init__(self, plugins: Iterable[Plugin]) -> None:
        self._plugins: dict[str, Plugin] = {}
        for plugin in plugins:
            plugin_id = plugin.meta.plugin_id
            if plugin_id in self._plugins:
                raise ValueError(f"Duplicate plugin id: {plugin_id}")
            self._plugins[plugin_id] = plugin
        self._order = _topological_order(self._plugins)

    @classmethod
    def discover(cls, module_names: Iterable[str] = BUILTIN_PLUGIN_MODULES) -> PluginRegistry:
        """Import plugin modules and build a registry from their ``Check`` classes.

        A module that fails to import or does not follow the plugin contract is
        skipped with a warning, so one broken plugin cannot take the scanner down.
        """
        return cls(p for p in (_load_module_plugin(name) for name in module_names) if p)

    def __contains__(self, plugin_id: object) -> bool:
        return plugin_id in self._plugins

    def __iter__(self) -> Iterator[Plugin]:
        return iter(self._plugins.values())

    def __len__(self) -> int:
        return len(self._plugins)

    def get(self, plugin_id: str) -> Plugin:
        return self._plugins[plugin_id]

    def execution_order(self) -> list[str]:
        """All plugin ids, each one after the plugins it depends on."""
        return list(self._order)

    def resolve_enabled(self, selection: Mapping[str, bool]) -> list[str]:
        """Plugin ids to run for a profile selection, in execution order.

        - an empty selection enables the plugins that are on by default;
        - a plugin absent from a non-empty selection keeps its default, so
          existing profiles pick up newly added plugins;
        - hard dependencies of an enabled plugin are enabled too.
        """
        enabled = {
            plugin_id
            for plugin_id, plugin in self._plugins.items()
            if selection.get(plugin_id, plugin.meta.enabled_by_default)
        }
        self._add_hard_dependencies(enabled)
        return [plugin_id for plugin_id in self._order if plugin_id in enabled]

    def _add_hard_dependencies(self, enabled: set[str]) -> None:
        pending = list(enabled)
        while pending:
            plugin = self._plugins[pending.pop()]
            for dependency in plugin.meta.depends_on:
                if dependency in self._plugins and dependency not in enabled:
                    enabled.add(dependency)
                    pending.append(dependency)


def _load_module_plugin(module_name: str) -> Plugin | None:
    full_name = f"{_PLUGIN_PACKAGE}.{module_name}"
    try:
        module = importlib.import_module(full_name)
    except Exception as exc:  # any import-time failure must not stop the scanner
        logger.warning("Failed to import plugin %s: %s", full_name, exc)
        return None

    meta = getattr(module, "META", None)
    check_cls = getattr(module, "Check", None)
    if not isinstance(meta, PluginMeta) or not (isinstance(check_cls, type) and issubclass(check_cls, Plugin)):
        logger.warning("Plugin %s must expose META: PluginMeta and Check(Plugin) — skipped", full_name)
        return None
    return check_cls(meta)


def _topological_order(plugins: Mapping[str, Plugin]) -> list[str]:
    """Kahn's algorithm. Dependencies on unknown plugins are ignored; plugins
    caught in a cycle are appended at the end, in registration order."""
    dependencies = {
        plugin_id: plugin.meta.ordering_dependencies & plugins.keys()
        for plugin_id, plugin in plugins.items()
    }
    dependents: dict[str, list[str]] = {plugin_id: [] for plugin_id in plugins}
    for plugin_id, deps in dependencies.items():
        for dependency in deps:
            dependents[dependency].append(plugin_id)

    remaining = {plugin_id: len(deps) for plugin_id, deps in dependencies.items()}
    ready = deque(plugin_id for plugin_id, count in remaining.items() if count == 0)
    order: list[str] = []
    while ready:
        plugin_id = ready.popleft()
        order.append(plugin_id)
        for dependent in dependents[plugin_id]:
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                ready.append(dependent)

    unresolved = [plugin_id for plugin_id in plugins if plugin_id not in order]
    if unresolved:
        logger.warning("Plugin dependency cycle for: %s", unresolved)
    return order + unresolved


@functools.lru_cache(maxsize=1)
def builtin_registry() -> PluginRegistry:
    """Registry of the built-in plugins, discovered once per process."""
    return PluginRegistry.discover()
