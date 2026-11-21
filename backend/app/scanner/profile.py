"""
Scan profile — which plugins run and with which options.

Profiles are stored as two JSON strings. They are parsed once, here, instead
of being re-decoded (with a silent fallback) at every place that reads them.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, replace
from typing import Any

logger = logging.getLogger(__name__)

WEB_AUTH_PLUGIN_ID = "web.auth"


@dataclass(frozen=True)
class ScanProfile:
    plugin_selection: dict[str, bool] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, plugin_selection_json: str | None, options_json: str | None) -> ScanProfile:
        return cls(
            plugin_selection={k: bool(v) for k, v in _json_object(plugin_selection_json, "plugin_selection_json").items()},
            options=_json_object(options_json, "options_json"),
        )

    def with_web_auth(self, web_auth: dict[str, Any] | None) -> ScanProfile:
        """Apply a per-job web authentication override.

        The override replaces the profile's own ``web_auth`` options and turns
        the web authentication plugin on, so users do not have to remember to.
        """
        if not web_auth or not web_auth.get("type"):
            return self
        return replace(
            self,
            options={**self.options, "web_auth": web_auth},
            plugin_selection={**self.plugin_selection, WEB_AUTH_PLUGIN_ID: True},
        )


def _json_object(text: str | None, field_name: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("Ignoring invalid %s in scan profile", field_name)
        return {}
    if not isinstance(value, dict):
        logger.warning("Ignoring non-object %s in scan profile", field_name)
        return {}
    return value
