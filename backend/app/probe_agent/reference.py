"""
Reference data on a probe: what the plugins read through
``ctx.resources.reference``, fetched from the platform.

- Datasets (KEV, CMS map, OSV…) are cached on disk with the platform's
  ETag: a dataset is downloaded again only when it changed. If the platform
  cannot be reached, the cached copy is used.
- The CVE catalog is looked up on the platform for the products a scan
  found (a few hundred records, not the whole NVD). While the platform's
  catalog is incomplete (NVD import running), it is completed with the
  nvd_cpe_cve dataset, as the platform itself does
  (``app.cve.catalogs.cve_catalog``).

Call :meth:`RemoteReferenceData.refresh` before each job: it reads the
current versions once, so a scan sees one consistent set.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Collection
from pathlib import Path
from typing import Any

from app.cve.cpe import ProductKey
from app.cve.matcher import CompositeCveCatalog, CveCatalog, CveRecord, InMemoryCveCatalog
from app.probe_agent.platform import PlatformClient, PlatformUnavailable

logger = logging.getLogger(__name__)

NVD_DATASET_KIND = "nvd_cpe_cve"
_SAFE_KIND = re.compile(r"^[a-z0-9_]+$")


class RemoteCveCatalog:
    """CVE records of the platform's catalog, asked once per product."""

    def __init__(self, client: PlatformClient) -> None:
        self._client = client
        self._known: dict[ProductKey, list[CveRecord]] = {}

    def records_for(self, products: Collection[ProductKey]) -> list[CveRecord]:
        missing = {p for p in products if p not in self._known}
        if missing:
            for product in missing:
                self._known[product] = []
            for item in self._client.cve_records(missing):
                record = CveRecord.from_flattened(item)
                if record is None:
                    continue
                for match in record.matches:
                    key = match.cpe.product_key
                    if key in missing and record not in self._known[key]:
                        self._known[key].append(record)
        seen: set[str] = set()
        records = []
        for product in products:
            for record in self._known.get(product, []):
                if record.cve_id not in seen:
                    seen.add(record.cve_id)
                    records.append(record)
        return records


class RemoteReferenceData:
    def __init__(self, client: PlatformClient, cache_dir: Path) -> None:
        self._client = client
        self._cache_dir = cache_dir
        self._status: dict[str, Any] = {}
        self._loaded: dict[str, list[list[Any]]] = {}

    def refresh(self) -> None:
        """Reads the current dataset versions; keeps the previous ones if the
        platform cannot be reached."""
        self._loaded = {}
        try:
            self._status = self._client.reference_status()
        except PlatformUnavailable as exc:
            logger.warning("Reference data status unavailable, using cached datasets: %s", exc)

    def datasets(self, kind: str) -> list[list[Any]]:
        if kind not in self._loaded:
            self._loaded[kind] = self._dataset(kind)
        return self._loaded[kind]

    def cve_catalog(self) -> CveCatalog:
        remote = RemoteCveCatalog(self._client)
        if self._status.get("cve_catalog_complete", False):
            return remote
        local = InMemoryCveCatalog.from_flattened(
            item for data in self.datasets(NVD_DATASET_KIND) for item in (data or [])
        )
        return CompositeCveCatalog([remote, local])

    def _dataset(self, kind: str) -> list[list[Any]]:
        if not _SAFE_KIND.match(kind):
            raise ValueError(f"Invalid dataset kind: {kind!r}")
        content_path, etag_path = self._cache_dir / f"{kind}.json", self._cache_dir / f"{kind}.etag"
        cached_etag = etag_path.read_text().strip() if etag_path.is_file() and content_path.is_file() else None
        current = (self._status.get("datasets") or {}).get(kind)
        if cached_etag and cached_etag == current:
            return _read(content_path)
        try:
            fetched = self._client.dataset(kind, cached_etag)
        except PlatformUnavailable:
            if cached_etag:
                logger.warning("Platform unreachable: using the cached %s dataset", kind)
                return _read(content_path)
            raise
        if fetched is None:  # still current
            return _read(content_path)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(content_path, json.dumps(fetched.content))
        _write_atomic(etag_path, fetched.etag)
        logger.info("Dataset %s updated (%s)", kind, fetched.etag)
        return fetched.content


def _read(path: Path) -> list[list[Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_atomic(path: Path, text: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
