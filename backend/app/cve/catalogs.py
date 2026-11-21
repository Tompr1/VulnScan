"""
Which CVE catalog a scan uses.

- While the NVD full import is still running, the database holds only part
  of the history: it is combined with the workspace's JSON datasets (the
  recent 120-day window), so nothing that used to match is lost.
- Once the full import is done, the database alone is used and the JSON
  datasets are no longer loaded (~0.5 GB of RAM saved per scan).
"""
from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Sequence

from sqlalchemy.orm import Session

from app.cve.cpe import ProductKey
from app.cve.dataset_loader import load_json
from app.cve.matcher import CveCatalog, CveRecord, InMemoryCveCatalog
from app.cve.sql_catalog import SqlCveCatalog, SqlSyncStateStore
from app.db import models

NVD_DATASET_KIND = "nvd_cpe_cve"


class CompositeCveCatalog:
    """Several catalogs read as one; for a CVE present in more than one, the
    first catalog wins."""

    def __init__(self, catalogs: Sequence[CveCatalog]) -> None:
        self._catalogs = catalogs

    def records_for(self, products: Collection[ProductKey]) -> list[CveRecord]:
        seen: set[str] = set()
        records = []
        for catalog in self._catalogs:
            for record in catalog.records_for(products):
                if record.cve_id not in seen:
                    seen.add(record.cve_id)
                    records.append(record)
        return records


def workspace_cve_catalog(
    workspace_id: int,
    session_factory: Callable[[], Session],
    load_dataset: Callable[[str], Iterable] = load_json,
) -> CveCatalog:
    database = SqlCveCatalog(session_factory)
    if SqlSyncStateStore(session_factory).load().full_import_done:
        return database
    datasets = InMemoryCveCatalog.from_flattened(
        item for path in _nvd_dataset_paths(workspace_id, session_factory) for item in (load_dataset(path) or [])
    )
    return CompositeCveCatalog([database, datasets])


def _nvd_dataset_paths(workspace_id: int, session_factory: Callable[[], Session]) -> list[str]:
    with session_factory() as db:
        return [
            row.path
            for row in db.query(models.CveDataset.path).filter(
                models.CveDataset.workspace_id == workspace_id,
                models.CveDataset.kind == NVD_DATASET_KIND,
                models.CveDataset.enabled.is_(True),
            )
        ]
