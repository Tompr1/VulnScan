"""
Scan progress reporting, written to the job row so the UI can poll it.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

RUNNING = "running"


class ThrottledProgressWriter:
    """Progress callback for the scan engine.

    Each plugin transition produces a JSON progress document. ``running``
    updates closer than ``min_interval`` seconds to the previous write are
    dropped; terminal updates (done/timeout/error) are always written so the
    UI never misses a final state. Writes run off the event loop: a blocking
    database call on the loop is what let a drained connection pool stall
    whole scans.
    """

    def __init__(
        self,
        write: Callable[[str], None],
        monotonic: Callable[[], float] = time.monotonic,
        min_interval: float = 2.0,
        max_log_entries: int = 20,
    ) -> None:
        self._write = write
        self._monotonic = monotonic
        self._min_interval = min_interval
        self._max_log_entries = max_log_entries
        self._started = monotonic()
        self._last_write: float | None = None
        self._plugin_log: dict[str, dict[str, Any]] = {}

    async def __call__(self, step: int, total: int, plugin_id: str, plugin_name: str, status: str) -> None:
        now = self._monotonic()
        elapsed = round(now - self._started, 1)
        self._plugin_log[plugin_id] = {"plugin_id": plugin_id, "name": plugin_name, "status": status, "t": elapsed}

        if status == RUNNING and self._last_write is not None and now - self._last_write < self._min_interval:
            return
        self._last_write = now
        document = self._document(step, total, plugin_id, plugin_name, status, elapsed)
        await asyncio.to_thread(self._write, json.dumps(document))

    def _document(self, step: int, total: int, plugin_id: str, plugin_name: str, status: str, elapsed: float) -> dict[str, Any]:
        finished_steps = step + (0 if status == RUNNING else 1)
        return {
            "progress": {
                "step": step,
                "total": total,
                "pct": round(finished_steps / max(total, 1) * 100),
                "current_plugin": plugin_id,
                "current_name": plugin_name,
                "status": status,
                "elapsed": elapsed,
                "plugins": list(self._plugin_log.values())[-self._max_log_entries:],
            }
        }
