"""
CVE matching — finds the CVEs affecting a set of installed products.

Shared by every source of installed products (network fingerprints, SSH
package inventories, and soon MDM inventories). The CVE data comes from a
:class:`CveCatalog`, so the same matching runs against the JSON datasets
today and against the database-backed NVD catalog tomorrow.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.cve.cpe import Cpe, CpeMatch, ProductKey


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    summary: str = ""
    severity: str = "medium"
    cvss: float | None = None
    references: tuple[str, ...] = ()
    matches: tuple[CpeMatch, ...] = ()

    @classmethod
    def from_flattened(cls, item: Mapping[str, Any]) -> CveRecord | None:
        """Build from one entry of the flattened NVD dataset (nvd_flatten.py)."""
        cve_id = item.get("cve") or ""
        if not cve_id.startswith("CVE-"):
            return None
        matches = tuple(m for m in (CpeMatch.from_nvd(raw) for raw in item.get("matches") or []) if m)
        return cls(
            cve_id=cve_id,
            summary=item.get("summary") or "",
            severity=item.get("severity") or "medium",
            cvss=item.get("cvss"),
            references=tuple(item.get("refs") or ()),
            matches=matches,
        )

    def to_flattened(self) -> dict[str, Any]:
        """The flattened NVD form :meth:`from_flattened` reads back."""
        return {
            "cve": self.cve_id,
            "summary": self.summary,
            "severity": self.severity,
            "cvss": self.cvss,
            "refs": list(self.references),
            "matches": [match.to_nvd() for match in self.matches],
        }


@dataclass(frozen=True)
class ProductCandidate:
    """An installed product to check. ``context`` is carried untouched into
    the hit, so each caller keeps its own extra data (confidence, package…)."""

    cpe: Cpe
    version: str | None
    context: Mapping[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class CveHit:
    record: CveRecord
    match: CpeMatch
    candidate: ProductCandidate


class CveCatalog(Protocol):
    def records_for(self, products: Collection[ProductKey]) -> Iterable[CveRecord]:
        """CVE records having at least one configuration on these products."""


class InMemoryCveCatalog:
    """Catalog indexed by product, built from already-loaded records."""

    def __init__(self, records: Iterable[CveRecord]) -> None:
        self._records: list[CveRecord] = []
        self._by_product: dict[ProductKey, list[int]] = defaultdict(list)
        for record in records:
            position = len(self._records)
            self._records.append(record)
            for key in {match.cpe.product_key for match in record.matches}:
                self._by_product[key].append(position)

    @classmethod
    def from_flattened(cls, items: Iterable[Mapping[str, Any]]) -> InMemoryCveCatalog:
        return cls(r for r in (CveRecord.from_flattened(item) for item in items) if r)

    def __len__(self) -> int:
        return len(self._records)

    def records_for(self, products: Collection[ProductKey]) -> list[CveRecord]:
        positions = sorted({p for key in products for p in self._by_product.get(key, ())})
        return [self._records[p] for p in positions]


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


def find_vulnerabilities(catalog: CveCatalog, candidates: Iterable[ProductCandidate]) -> list[CveHit]:
    """One hit per (CVE, vulnerable configuration): the first candidate it affects."""
    by_product: dict[ProductKey, list[ProductCandidate]] = defaultdict(list)
    for candidate in candidates:
        by_product[candidate.cpe.product_key].append(candidate)
    if not by_product:
        return []

    hits: list[CveHit] = []
    for record in catalog.records_for(by_product.keys()):
        for match in record.matches:
            affected = next(
                (c for c in by_product.get(match.cpe.product_key, ()) if match.affects(c.cpe, c.version)),
                None,
            )
            if affected is not None:
                hits.append(CveHit(record, match, affected))
    return hits
