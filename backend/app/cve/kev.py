"""
CISA Known Exploited Vulnerabilities — CVEs attackers already exploit.

Read from the workspace's ``cisa_kev`` dataset (the JSON written by the
dataset refresh: one row per CVE with ``cve``/``cveID``, ``dateAdded``,
``dueDate``, ``knownRansomwareCampaignUse``). Rows are parsed at the
boundary; a malformed row is skipped.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol

from sqlalchemy.orm import Session

from app.cve.dataset_loader import load_json
from app.cve.reference_datasets import enabled_dataset_paths

logger = logging.getLogger(__name__)

KEV_DATASET_KIND = "cisa_kev"


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: date | None = None
    due_date: date | None = None
    ransomware: bool = False  # used in ransomware campaigns

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> KevEntry | None:
        if not isinstance(row, Mapping):
            return None
        cve_id = str(row.get("cve") or row.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            return None
        return cls(
            cve_id=cve_id,
            date_added=_date(row.get("dateAdded")),
            due_date=_date(row.get("dueDate")),
            ransomware=str(row.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
        )


class KevCatalog(Protocol):
    def get(self, cve_id: str) -> KevEntry | None: ...


class InMemoryKevCatalog:
    def __init__(self, entries: Iterable[KevEntry] = ()) -> None:
        self._entries = {entry.cve_id: entry for entry in entries}

    @classmethod
    def from_rows(cls, rows: Iterable[Any]) -> InMemoryKevCatalog:
        return cls(entry for entry in map(KevEntry.from_row, rows) if entry is not None)

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, cve_id: str) -> KevEntry | None:
        return self._entries.get(cve_id.upper())


def kev_catalog(
    session_factory: Callable[[], Session],
    load_dataset: Callable[[str], Any] = load_json,
) -> InMemoryKevCatalog:
    """The enabled KEV datasets, shared by every client (empty when none is loaded)."""
    with session_factory() as db:
        paths = enabled_dataset_paths(db, KEV_DATASET_KIND)
    rows: list[Any] = []
    for path in paths:
        data = load_dataset(path)
        if isinstance(data, list):
            rows += data
        else:
            logger.warning("KEV dataset %s is not a list — ignored", path)
    return InMemoryKevCatalog.from_rows(rows)


def _date(raw: Any) -> date | None:
    try:
        return date.fromisoformat(str(raw or "").strip()[:10])
    except ValueError:
        return None
