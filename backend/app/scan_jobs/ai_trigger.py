"""
Automatic AI analysis — queued after a scan when the workspace enabled it.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from app.core.job_queue import AiAnalysisQueue
from app.core.workspace_settings import AUTO_AI_ANALYSIS_KEY, get_workspace_setting
from app.db import models
from app.scan_jobs.repository import SessionFactory

logger = logging.getLogger(__name__)

PROVIDER_PREFERENCE = ("claude_cli", "claude_api", "azure_openai", "gemini")
DEFAULT_MODE = "validate"
_ACTIVE_STATUSES = ("queued", "running")


def choose_ai_provider(configured: str, available: Sequence[str]) -> str | None:
    """The configured provider, else the first available one by preference."""
    if configured:
        return configured
    preferred = next((p for p in PROVIDER_PREFERENCE if p in available), None)
    return preferred or (available[0] if available else None)


class AutoAnalysisTrigger(Protocol):
    def maybe_queue(self, job_id: int, workspace_id: int, saved_findings: int) -> bool:
        """Queue an analysis if the workspace wants one; True when queued."""


class SqlAutoAnalysisTrigger:
    def __init__(
        self,
        session_factory: SessionFactory,
        queue: AiAnalysisQueue,
        available_providers: Callable[[], list[dict[str, Any]]],
    ) -> None:
        self._session_factory = session_factory
        self._queue = queue
        self._available_providers = available_providers

    def maybe_queue(self, job_id: int, workspace_id: int, saved_findings: int) -> bool:
        if saved_findings == 0:
            return False
        with self._session_factory() as db:
            config = get_workspace_setting(db, workspace_id, AUTO_AI_ANALYSIS_KEY, {})
            if not config.get("enabled"):
                return False

            available = [p["id"] for p in self._available_providers()]
            provider = choose_ai_provider(str(config.get("provider") or ""), available)
            if provider is None:
                logger.info("Auto AI analysis enabled but no provider available — skipped")
                return False
            if self._has_active_analysis(db, job_id):
                return False

            analysis = models.AiAnalysis(
                workspace_id=workspace_id,
                job_id=job_id,
                provider=provider,
                mode=config.get("mode", DEFAULT_MODE),
                status="queued",
                progress_json=json.dumps({"pct": 0, "step": "Auto-queued after scan..."}),
            )
            db.add(analysis)
            db.commit()
            analysis_id = analysis.id

        self._queue.enqueue_ai_analysis(analysis_id)
        logger.info("Auto AI analysis #%d queued for job #%d (provider=%s)", analysis_id, job_id, provider)
        return True

    @staticmethod
    def _has_active_analysis(db, job_id: int) -> bool:
        return (
            db.query(models.AiAnalysis.id)
            .filter(models.AiAnalysis.job_id == job_id, models.AiAnalysis.status.in_(_ACTIVE_STATUSES))
            .first()
            is not None
        )
