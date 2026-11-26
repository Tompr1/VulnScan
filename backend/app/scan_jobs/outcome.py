"""
Life cycle of a scan job: its statuses and how it ended.

Plain values with no database behind them: the part of a scan that runs on
a probe uses them too.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_MAX_TRACEBACK_CHARS = 2000


class JobStatus(StrEnum):
    """Statuses of a ``scan_jobs`` row.

    queued -> running -> processing -> done (-> analyzing -> done)
       \\-> cancelled      \\-> failed     \\-> failed

    ``processing``: the scan has ended and its findings are being scored and
    saved. Results are accepted only once, by the call that moves the job
    from ``running`` to ``processing``.
    """

    QUEUED = "queued"
    RUNNING = "running"
    PROCESSING = "processing"
    DONE = "done"
    FAILED = "failed"
    ANALYZING = "analyzing"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class JobFailure:
    error: str
    error_type: str
    detail: str | None = None
    traceback: str | None = None

    def to_meta(self) -> dict[str, Any]:
        meta: dict[str, Any] = {"error": self.error[:500], "error_type": self.error_type}
        if self.detail:
            meta["error_detail"] = self.detail
        if self.traceback:
            meta["traceback"] = self.traceback[:_MAX_TRACEBACK_CHARS]
        return meta

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.error, "error_type": self.error_type, "detail": self.detail, "traceback": self.traceback}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JobFailure:
        return cls(
            error=str(data.get("error") or ""),
            error_type=str(data.get("error_type") or "unhandled"),
            detail=data.get("detail"),
            traceback=data.get("traceback"),
        )


def unknown_scan_type(scan_type: str) -> JobFailure:
    return JobFailure(error=f"Unknown scan type: {scan_type}", error_type="configuration")


@dataclass(frozen=True)
class JobCompletion:
    findings_total: int
    findings_saved: int
    findings_dropped: int
    min_confidence_threshold: float

    def to_meta(self) -> dict[str, Any]:
        return {
            "findings_total": self.findings_total,
            "findings_saved": self.findings_saved,
            "findings_dropped": self.findings_dropped,
            "min_confidence_threshold": self.min_confidence_threshold,
        }
