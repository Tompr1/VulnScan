"""
endoflife.date as a SupportCatalog.

``GET https://endoflife.date/api/<product>.json`` lists the cycles of a
product. Entries are parsed by Pydantic at the boundary: an invalid entry is
skipped, not fatal. Each product is fetched once per catalog instance (one
audit run), failures included, so 300 devices never mean 300 requests.

The HTTP layer is an injected ``httpx.Client``: tests plug a MockTransport.
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.inventory.audit.lifecycle import CatalogUnavailableError, SupportCycle

logger = logging.getLogger(__name__)

ENDOFLIFE_API = "https://endoflife.date/api"
_TIMEOUT_SECONDS = 20


class EndOfLifeCycle(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    cycle: str = Field(min_length=1, max_length=64)
    release_label: str | None = Field(alias="releaseLabel", default=None, max_length=128)
    eol: bool | date = False
    latest: str | None = Field(default=None, max_length=64)

    @field_validator("cycle", "latest", mode="before")
    @classmethod
    def _numbers_as_text(cls, value: Any) -> Any:
        # A few products publish cycles as JSON numbers (8 instead of "8").
        return str(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else value

    def to_cycle(self) -> SupportCycle:
        return SupportCycle(
            name=self.cycle,
            label=self.release_label or self.cycle,
            support_ends_on=self.eol if isinstance(self.eol, date) else None,
            ended=self.eol is True,
            latest=self.latest,
        )


class EndOfLifeDateCatalog:
    def __init__(self, http: httpx.Client | None = None, base_url: str = ENDOFLIFE_API) -> None:
        self._http = http or httpx.Client(timeout=_TIMEOUT_SECONDS, headers={"User-Agent": "VulnScan"})
        self._base_url = base_url.rstrip("/")
        self._cache: dict[str, tuple[SupportCycle, ...] | CatalogUnavailableError] = {}

    def cycles(self, product: str) -> tuple[SupportCycle, ...]:
        if product not in self._cache:
            try:
                self._cache[product] = self._fetch(product)
            except CatalogUnavailableError as exc:
                logger.warning("%s", exc)
                self._cache[product] = exc
        cached = self._cache[product]
        if isinstance(cached, CatalogUnavailableError):
            raise cached
        return cached

    def _fetch(self, product: str) -> tuple[SupportCycle, ...]:
        url = f"{self._base_url}/{product}.json"
        try:
            response = self._http.get(url)
        except httpx.HTTPError as exc:
            raise CatalogUnavailableError(f"endoflife.date unreachable for {product}: {exc}") from exc
        if response.status_code != 200:
            raise CatalogUnavailableError(f"endoflife.date answered HTTP {response.status_code} for {product}")
        try:
            entries = response.json()
        except ValueError as exc:
            raise CatalogUnavailableError(f"endoflife.date sent invalid JSON for {product}") from exc
        if not isinstance(entries, list):
            raise CatalogUnavailableError(f"endoflife.date sent an unexpected document for {product}")
        return tuple(cycle for cycle in map(_parse_entry, entries) if cycle is not None)


def _parse_entry(entry: Any) -> SupportCycle | None:
    try:
        return EndOfLifeCycle.model_validate(entry).to_cycle()
    except (ValidationError, ValueError) as exc:
        logger.debug("Skipping invalid endoflife.date entry %r: %s", entry, exc)
        return None
