"""
Database-backed CVE catalog.

Only the CVEs of the products being checked are read, so matching the whole
NVD history (300k+ CVEs) costs a few indexed queries instead of loading a
multi-gigabyte JSON file into every worker.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable, Collection, Iterator, Sequence
from itertools import islice

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.cve.cpe import Cpe, CpeMatch, ProductKey, VersionRange, canonical_vendor
from app.cve.matcher import CveRecord
from app.cve.nvd import NvdCve
from app.cve.nvd_sync import SyncState
from app.db import models

SessionFactory = Callable[[], Session]

_BATCH = 500  # keeps IN (...) / OR clauses well below database limits


class SqlCveCatalog:
    """CveCatalog for lookups and CveStore for the importer."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def count(self) -> int:
        with self._session_factory() as db:
            return db.query(func.count(models.CveEntry.cve_id)).scalar() or 0

    def records_for(self, products: Collection[ProductKey]) -> list[CveRecord]:
        if not products:
            return []
        with self._session_factory() as db:
            matches: dict[str, list[CpeMatch]] = defaultdict(list)
            for batch in _batches(sorted(products)):
                condition = or_(*(and_(models.CveCpeMatch.vendor == v, models.CveCpeMatch.product == p) for v, p in batch))
                for row in db.query(models.CveCpeMatch).filter(condition).order_by(models.CveCpeMatch.id):
                    matches[row.cve_id].append(_match_of(row))

            records = []
            for batch in _batches(sorted(matches)):
                for entry in db.query(models.CveEntry).filter(models.CveEntry.cve_id.in_(batch)):
                    records.append(_record_of(entry, matches[entry.cve_id]))
            return sorted(records, key=lambda r: r.cve_id)

    def upsert(self, cves: Sequence[NvdCve]) -> None:
        """Insert or replace CVEs with all their CPE matches, atomically."""
        if not cves:
            return
        latest = {c.record.cve_id: c for c in cves}  # a page may repeat an id
        with self._session_factory() as db:
            for batch in _batches(list(latest)):
                db.query(models.CveCpeMatch).filter(models.CveCpeMatch.cve_id.in_(batch)).delete(synchronize_session=False)
                db.query(models.CveEntry).filter(models.CveEntry.cve_id.in_(batch)).delete(synchronize_session=False)
            for cve in latest.values():
                db.add(_entry_row(cve))
                db.add_all(_match_rows(cve))
            db.commit()


class SqlSyncStateStore:
    def __init__(self, session_factory: SessionFactory, source: str = "nvd") -> None:
        self._session_factory = session_factory
        self._source = source

    def load(self) -> SyncState:
        with self._session_factory() as db:
            row = db.get(models.CveSyncState, self._source)
            if row is None:
                return SyncState()
            return SyncState(
                full_import_started_at=row.full_import_started_at,
                full_import_next_index=row.full_import_next_index or 0,
                full_import_total=row.full_import_total,
                full_import_completed_at=row.full_import_completed_at,
                synced_until=row.synced_until,
            )

    def save(self, state: SyncState) -> None:
        with self._session_factory() as db:
            row = db.get(models.CveSyncState, self._source) or models.CveSyncState(source=self._source)
            row.full_import_started_at = state.full_import_started_at
            row.full_import_next_index = state.full_import_next_index
            row.full_import_total = state.full_import_total
            row.full_import_completed_at = state.full_import_completed_at
            row.synced_until = state.synced_until
            db.merge(row)
            db.commit()


def _batches(items: Sequence) -> Iterator[list]:
    iterator = iter(items)
    while batch := list(islice(iterator, _BATCH)):
        yield batch


def _entry_row(cve: NvdCve) -> models.CveEntry:
    record = cve.record
    return models.CveEntry(
        cve_id=record.cve_id,
        summary=record.summary,
        severity=record.severity,
        cvss=record.cvss,
        references_json=json.dumps(list(record.references)),
        published_at=cve.published_at,
        last_modified_at=cve.last_modified_at,
    )


def _match_rows(cve: NvdCve) -> list[models.CveCpeMatch]:
    return [
        models.CveCpeMatch(
            cve_id=cve.record.cve_id,
            part=match.cpe.part[:1],
            vendor=canonical_vendor(match.cpe.vendor),
            product=match.cpe.product,
            version=match.cpe.version,
            start_including=match.versions.start_including,
            start_excluding=match.versions.start_excluding,
            end_including=match.versions.end_including,
            end_excluding=match.versions.end_excluding,
        )
        for match in cve.record.matches
    ]


def _match_of(row: models.CveCpeMatch) -> CpeMatch:
    return CpeMatch(
        Cpe(part=row.part, vendor=row.vendor, product=row.product, version=row.version or "*"),
        VersionRange(row.start_including, row.start_excluding, row.end_including, row.end_excluding),
    )


def _record_of(entry: models.CveEntry, matches: list[CpeMatch]) -> CveRecord:
    return CveRecord(
        cve_id=entry.cve_id,
        summary=entry.summary or "",
        severity=entry.severity or "medium",
        cvss=entry.cvss,
        references=tuple(json.loads(entry.references_json or "[]")),
        matches=tuple(matches),
    )
