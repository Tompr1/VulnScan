"""
NVD catalog synchronisation.

1. Full import: the whole NVD (300k+ CVEs) page by page. Progress is saved
   after every page, so a run stopped by its time budget, a crash or a
   redeploy resumes where it stopped.
2. Incremental: afterwards, only the CVEs modified since the last sync, in
   windows of at most 120 days (an NVD API limit).

The changes made *during* a full import are caught by the first incremental
run, which starts from the moment the full import began.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.cve.nvd import NvdCve, NvdPage, parse_page

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_MODIFIED_WINDOW = timedelta(days=120)

ModifiedWindow = tuple[datetime, datetime]


@dataclass
class SyncState:
    full_import_started_at: datetime | None = None
    full_import_next_index: int = 0
    full_import_total: int | None = None
    full_import_completed_at: datetime | None = None
    synced_until: datetime | None = None

    @property
    def full_import_done(self) -> bool:
        return self.full_import_completed_at is not None


@dataclass(frozen=True)
class SyncReport:
    mode: str  # "full" | "incremental"
    complete: bool
    pages: int = 0
    cves: int = 0
    skipped: int = 0
    message: str = ""


class NvdFeed(Protocol):
    def fetch(self, start_index: int, page_size: int, modified: ModifiedWindow | None = None) -> NvdPage: ...


class CveStore(Protocol):
    def upsert(self, cves: Sequence[NvdCve]) -> None: ...


class SyncStateStore(Protocol):
    def load(self) -> SyncState: ...

    def save(self, state: SyncState) -> None: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NvdCatalogSync:
    def __init__(
        self,
        feed: NvdFeed,
        store: CveStore,
        states: SyncStateStore,
        page_size: int = 200,
        budget_seconds: float = 6600.0,
        pause: Callable[[], None] = lambda: None,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= page_size <= 2000:
            raise ValueError("NVD pages hold between 1 and 2000 results")
        self._feed = feed
        self._store = store
        self._states = states
        self._page_size = page_size
        self._budget_seconds = budget_seconds
        self._pause = pause
        self._clock = clock
        self._monotonic = monotonic

    def run(self) -> SyncReport:
        state = self._states.load()
        deadline = self._monotonic() + self._budget_seconds
        if state.full_import_done:
            return self._incremental(state, deadline)
        return self._full_import(state, deadline)

    def _full_import(self, state: SyncState, deadline: float) -> SyncReport:
        if state.full_import_started_at is None:
            state.full_import_started_at = self._clock()
            self._states.save(state)
        tally = _Tally()
        while True:
            if self._monotonic() >= deadline:
                return tally.report("full", False, f"time budget used; resumes at index {state.full_import_next_index}")
            page = self._fetch(state.full_import_next_index, None, tally)
            state.full_import_next_index = page.next_index
            state.full_import_total = page.total_results
            finished = page.raw_count == 0 or page.next_index >= page.total_results
            if finished:
                state.full_import_completed_at = self._clock()
                state.synced_until = state.full_import_started_at
            self._states.save(state)
            logger.info("NVD full import: %d/%d", state.full_import_next_index, page.total_results)
            if finished:
                return tally.report("full", True, f"{page.total_results} CVEs in catalog")
            self._pause()

    def _incremental(self, state: SyncState, deadline: float) -> SyncReport:
        tally = _Tally()
        start = state.synced_until or state.full_import_completed_at
        for window in modified_windows(start, self._clock()):
            index = 0
            while True:
                if self._monotonic() >= deadline:
                    return tally.report("incremental", False, f"time budget used; resumes from {window[0].isoformat()}")
                page = self._fetch(index, window, tally)
                index = page.next_index
                if page.raw_count == 0 or index >= page.total_results:
                    break
                self._pause()
            state.synced_until = window[1]
            self._states.save(state)
        return tally.report("incremental", True, f"synced until {state.synced_until.isoformat() if state.synced_until else '-'}")

    def _fetch(self, start_index: int, window: ModifiedWindow | None, tally: _Tally) -> NvdPage:
        page = self._feed.fetch(start_index, self._page_size, window)
        self._store.upsert(page.cves)
        tally.add(page)
        return page


class _Tally:
    def __init__(self) -> None:
        self.pages = self.cves = self.skipped = 0

    def add(self, page: NvdPage) -> None:
        self.pages += 1
        self.cves += len(page.cves)
        self.skipped += page.skipped

    def report(self, mode: str, complete: bool, message: str) -> SyncReport:
        return SyncReport(mode, complete, self.pages, self.cves, self.skipped, message)


def modified_windows(start: datetime, end: datetime, size: timedelta = MAX_MODIFIED_WINDOW) -> Iterator[ModifiedWindow]:
    """Consecutive [start, end] windows no longer than ``size``."""
    while start < end:
        window_end = min(start + size, end)
        yield start, window_end
        start = window_end


class HttpNvdFeed:
    """NvdFeed over the NVD REST API. ``fetch_url(url, headers) -> bytes`` is
    injected so retries and timeouts stay the caller's policy."""

    def __init__(self, fetch_url: Callable[[str, Mapping[str, str]], bytes], api_key: str | None = None) -> None:
        self._fetch_url = fetch_url
        self._headers = {"Accept": "application/json", **({"apiKey": api_key} if api_key else {})}

    def fetch(self, start_index: int, page_size: int, modified: ModifiedWindow | None = None) -> NvdPage:
        query = f"startIndex={start_index}&resultsPerPage={page_size}"
        if modified:
            query += f"&lastModStartDate={_nvd_date(modified[0])}&lastModEndDate={_nvd_date(modified[1])}"
        return parse_page(json.loads(self._fetch_url(f"{NVD_API_URL}?{query}", self._headers)))


def _nvd_date(moment: datetime) -> str:
    """NVD expects extended ISO-8601 in UTC without offset: 2026-01-31T23:59:59.000"""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
