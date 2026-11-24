"""
Reference data of an inventory audit, shared by every client: endoflife.date,
the NVD catalog (database, plus the JSON datasets while the history import
runs) and the CISA KEV dataset — with the known gaps spelled out.
"""
from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from app.cve.catalogs import cve_catalog
from app.cve.kev import kev_catalog
from app.cve.sql_catalog import SqlSyncStateStore
from app.inventory.audit.base import ReferenceData
from app.inventory.audit.catalog import EndOfLifeDateCatalog
from app.inventory.audit.lifecycle import SupportCatalog

NVD_IMPORT_RUNNING = "The NVD history import is still running: CVEs older than the last 120 days may be missing until it completes."
NO_KEV_DATASET = ("No CISA KEV dataset is loaded: actively exploited CVEs are not flagged "
                  "(refresh the datasets under Configuration > Datasets).")


def load_reference_data(
    session_factory: Callable[[], Session],
    lifecycle: Callable[[], SupportCatalog] = EndOfLifeDateCatalog,
) -> ReferenceData:
    kev = kev_catalog(session_factory)
    notes = []
    if not SqlSyncStateStore(session_factory).load().full_import_done:
        notes.append(NVD_IMPORT_RUNNING)
    if len(kev) == 0:
        notes.append(NO_KEV_DATASET)
    return ReferenceData(
        lifecycle=lifecycle(),  # a fresh one per audit: lifecycle data is re-read every run
        cves=cve_catalog(session_factory),
        kev=kev,
        notes=tuple(notes),
    )
