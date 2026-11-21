"""
NVD API 2.0 — page model and parsing into catalog records.

https://nvd.nist.gov/developers/vulnerabilities

Raw JSON is turned into domain objects as soon as it arrives. A malformed
entry is skipped and counted instead of failing the whole page.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.cve.cpe import CpeMatch
from app.cve.matcher import CveRecord
from app.risk.severity import Severity

logger = logging.getLogger(__name__)

# CVSS versions by preference; "Primary" is NVD's own score, others come from CNAs.
_CVSS_METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_SEVERITIES = ("critical", "high", "medium", "low")
_MAX_REFERENCES = 25


@dataclass(frozen=True)
class NvdCve:
    record: CveRecord
    published_at: datetime | None
    last_modified_at: datetime | None


@dataclass(frozen=True)
class NvdPage:
    start_index: int
    total_results: int
    cves: tuple[NvdCve, ...]
    raw_count: int  # entries in the page, including the skipped ones

    @property
    def skipped(self) -> int:
        return self.raw_count - len(self.cves)

    @property
    def next_index(self) -> int:
        return self.start_index + self.raw_count


def parse_page(document: Mapping[str, Any]) -> NvdPage:
    entries = document.get("vulnerabilities") or []
    cves = []
    for entry in entries:
        cve = parse_vulnerability(entry)
        if cve is None:
            logger.warning("Skipping malformed NVD entry: %.200s", entry)
        else:
            cves.append(cve)
    return NvdPage(
        start_index=int(document.get("startIndex") or 0),
        total_results=int(document.get("totalResults") or 0),
        cves=tuple(cves),
        raw_count=len(entries),
    )


def parse_vulnerability(entry: Mapping[str, Any]) -> NvdCve | None:
    cve = entry.get("cve") if isinstance(entry, Mapping) else None
    if not isinstance(cve, Mapping):
        return None
    cve_id = cve.get("id") or ""
    if not cve_id.startswith("CVE-"):
        return None
    score, severity = _cvss(cve.get("metrics") or {})
    record = CveRecord(
        cve_id=cve_id,
        summary=_english_description(cve),
        severity=severity,
        cvss=score,
        references=tuple(r["url"] for r in cve.get("references") or [] if isinstance(r, Mapping) and r.get("url"))[
            :_MAX_REFERENCES
        ],
        matches=tuple(_cpe_matches(cve.get("configurations") or [])),
    )
    return NvdCve(record, _timestamp(cve.get("published")), _timestamp(cve.get("lastModified")))


def _cvss(metrics: Mapping[str, Any]) -> tuple[float | None, str]:
    for key in _CVSS_METRICS:
        candidates = [m for m in metrics.get(key) or [] if isinstance(m, Mapping)]
        if not candidates:
            continue
        chosen = next((m for m in candidates if str(m.get("type", "")).lower() == "primary"), candidates[0])
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)) and 0 <= score <= 10:
            severity = str(data.get("baseSeverity") or chosen.get("baseSeverity") or "").lower()
            return float(score), severity if severity in _SEVERITIES else Severity.from_score(score).value
    return None, "medium"  # not yet scored by NVD: keep it visible, not "info"


def _english_description(cve: Mapping[str, Any]) -> str:
    descriptions = [d for d in cve.get("descriptions") or [] if isinstance(d, Mapping) and d.get("value")]
    english = next((d for d in descriptions if d.get("lang") == "en"), None)
    return (english or (descriptions[0] if descriptions else {})).get("value", "")


def _cpe_matches(configurations: Any) -> Iterator[CpeMatch]:
    """Vulnerable CPE matches of every configuration node, without duplicates."""
    seen = set()
    for node in _nodes(configurations):
        for raw in node.get("cpeMatch") or []:
            if not isinstance(raw, Mapping) or raw.get("vulnerable") is False:
                continue
            match = CpeMatch.from_nvd(raw)
            if match is not None and match not in seen:
                seen.add(match)
                yield match


def _nodes(configurations: Any) -> Iterator[Mapping[str, Any]]:
    roots = configurations if isinstance(configurations, list) else [configurations]
    stack = []
    for root in roots:
        if isinstance(root, Mapping):
            stack.extend(n for n in root.get("nodes") or [] if isinstance(n, Mapping))
    while stack:
        node = stack.pop()
        yield node
        stack.extend(c for c in node.get("children") or [] if isinstance(c, Mapping))


def _timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
