"""
Threat Intel aggregator.

Fuses per-CVE data from the enabled NVD, CISA KEV, EPSS and vendor advisory
datasets. The datasets are shared by every client, and so is the result.

The fusion is done once per change of the datasets, by the datasets worker
(``rebuild``), and stored in the ``threat_intel_cves`` table; the API only
queries that table (``query``, ``detail``, ``stats``).

It used to be an in-memory cache of the API process with a 5-minute TTL:
every expiry reloaded ~150 MB of JSON inside a request, holding the GIL, so
the whole API stalled for 4 s per rebuild, and each request landing after the
expiry started its own rebuild (12 s and 1.8 GB for three, measured on the
lab VM). The sidebar asks for the stats every 12 s per open tab.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from sqlalchemy import case, delete, func, insert, or_
from sqlalchemy.orm import Session

from app.core.platform_settings import get_platform_setting, set_platform_setting
from app.cve.reference_datasets import REFRESH_LOCK_KEY, latest_dataset_path
from app.db import models
from app.threat_intel import exposure

logger = logging.getLogger("v0cday.threat_intel")

# The datasets the table is built from.
FEEDER_KINDS = ("nvd_cpe_cve", "cisa_kev", "epss", "vendor_advisories")
# Bump when the fusion changes: the next scheduler tick rebuilds the table.
BUILD_VERSION = 1
# Platform setting: the sources of the current table and what they held.
BUILD_KEY = "threat_intel_build"
# Redis key set while a rebuild is queued, so it is queued once.
REBUILD_QUEUED_KEY = "threat_intel_rebuild_queued"
REBUILD_QUEUED_TTL_SECONDS = 1800
_INSERT_BATCH = 2000

T = models.ThreatIntelCve


# ─── Loaders ────────────────────────────────────────────────────────────────

def _load_dataset_file(path: str) -> Any:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Threat Intel: could not load %s: %s", path, e)
        return None


def _normalise_nvd(raw: Any) -> list[dict]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and "vulnerabilities" in raw:
        return raw["vulnerabilities"]
    return []


def _vendor_product_from_cpe(cpe23: str) -> tuple[str, str]:
    """Best-effort vendor/product extraction from a CPE 2.3 URI."""
    parts = (cpe23 or "").split(":")
    if len(parts) >= 5:
        vendor = (parts[3] or "").replace("_", " ").strip()
        product = (parts[4] or "").replace("_", " ").strip()
        return vendor, product
    return "", ""


def _parse_iso_date(s: Any) -> date | None:
    if not s or not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except Exception:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def _float(value: Any) -> float | None:
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


# ─── Fusion (pure) ──────────────────────────────────────────────────────────

def merge_sources(nvd_raw: Any, kev_raw: Any, epss_raw: Any, va_raw: Any) -> tuple[dict[str, dict], list[str]]:
    """Per-CVE records fused from the raw datasets, and the datasets used."""
    merged: dict[str, dict[str, Any]] = {}
    loaded: list[str] = []

    # NVD — primary source for CVSS, summary, severity, CPE matches
    if nvd_raw:
        loaded.append("nvd")
        for row in _normalise_nvd(nvd_raw):
            cve_id = (row.get("cve") or row.get("id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            matches = row.get("matches") or []
            vendor, product = ("", "")
            if matches:
                vendor, product = _vendor_product_from_cpe(matches[0].get("cpe23", ""))

            merged[cve_id] = {
                "cve": cve_id,
                "summary": row.get("summary") or "",
                "cvss": _float(row.get("cvss")),
                "severity": (row.get("severity") or "").lower(),
                "vendor": vendor,
                "product": product,
                "matches": matches[:50],
                "refs": row.get("refs") or [],
                "vendor_advisories": row.get("vendor_advisories") or {},
                "epss": None,
                "epss_percentile": None,
                "kev": False,
                "kev_added": None,
                "kev_due": None,
                "ransomware": False,
                "kev_notes": "",
            }

    # CISA KEV — overlays exploitation status + ransomware flag
    if kev_raw and isinstance(kev_raw, list):
        loaded.append("kev")
        for row in kev_raw:
            cve_id = (row.get("cve") or row.get("cveID") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            rec = merged.get(cve_id)
            if rec is None:
                # KEV-only entries (no NVD match yet) — minimal record
                rec = {
                    "cve": cve_id,
                    "summary": row.get("notes") or "",
                    "cvss": None,
                    "severity": "",
                    "vendor": row.get("vendorProject") or "",
                    "product": row.get("product") or "",
                    "matches": [],
                    "refs": row.get("refs") or [],
                    "vendor_advisories": {},
                    "epss": None,
                    "epss_percentile": None,
                }
                merged[cve_id] = rec
            else:
                # Prefer KEV's vendor/product when present (more accurate than CPE-derived)
                if row.get("vendorProject"):
                    rec["vendor"] = row["vendorProject"]
                if row.get("product"):
                    rec["product"] = row["product"]

            rec["kev"] = True
            rec["kev_added"] = row.get("dateAdded") or None
            rec["kev_due"] = row.get("dueDate") or None
            rec["ransomware"] = (row.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
            rec["kev_notes"] = row.get("notes") or ""

    # EPSS — overlays exploitation probability
    if epss_raw and isinstance(epss_raw, list):
        loaded.append("epss")
        for row in epss_raw:
            cve_id = (row.get("cve") or "").strip().upper()
            rec = merged.get(cve_id)
            if rec is None:
                continue  # don't synthesise records from EPSS alone
            rec["epss"] = _float(row.get("epss")) or 0.0
            rec["epss_percentile"] = _float(row.get("percentile")) or 0.0

    # Vendor advisories — overlays additional vendor references
    if va_raw and isinstance(va_raw, dict):
        loaded.append("vendor_advisories")
        for cve_id_raw, advisories in va_raw.items():
            rec = merged.get(cve_id_raw.strip().upper())
            if rec is None or not isinstance(advisories, list):
                continue
            existing_va = rec.get("vendor_advisories") or {}
            for adv in advisories:
                if not isinstance(adv, dict):
                    continue
                known = existing_va.setdefault(adv.get("vendor", "unknown"), [])
                # Deduplicate by URL
                if adv.get("url") and adv["url"] not in {a.get("url") for a in known}:
                    known.append(adv)
            rec["vendor_advisories"] = existing_va

    return merged, loaded


def base_score(rec: dict) -> float:
    """Threat score without its KEV recency bonus (see ``recency_bonus``).

    Composite threat score, 0–100: 40% CVSS, 35% EPSS percentile, 15% KEV
    (with +3 ransomware kicker), 10% recency bonus on KEV add date.
    """
    cvss = _float(rec.get("cvss")) or 0.0
    epss_p = _float(rec.get("epss_percentile")) or 0.0
    score = (cvss / 10.0) * 40.0 + epss_p * 35.0
    if rec.get("kev"):
        score += 12.0
    if rec.get("ransomware"):
        score += 3.0
    return score


# (days since added to KEV, bonus), most recent first.
_RECENCY_STEPS = ((7, 10.0), (30, 7.0), (90, 4.0))


def recency_bonus(kev_added: date | None, today: date) -> float:
    if kev_added is None:
        return 0.0
    days = (today - kev_added).days
    for limit, bonus in _RECENCY_STEPS:
        if days <= limit:
            return bonus
    return 0.0


def _threat_score(base: float, kev_added: date | None, today: date) -> float:
    return round(min(max(base + recency_bonus(kev_added, today), 0.0), 100.0), 1)


def _row(rec: dict) -> dict[str, Any]:
    return {
        "cve": rec["cve"],
        "summary": rec.get("summary") or "",
        "cvss": _float(rec.get("cvss")),
        "severity": (rec.get("severity") or "")[:16],
        "vendor": rec.get("vendor") or "",
        "product": rec.get("product") or "",
        "epss": rec.get("epss"),
        "epss_percentile": rec.get("epss_percentile"),
        "kev": bool(rec.get("kev")),
        "kev_added": _parse_iso_date(rec.get("kev_added")),
        "kev_due": _parse_iso_date(rec.get("kev_due")),
        "ransomware": bool(rec.get("ransomware")),
        "base_score": base_score(rec),
        "details_json": json.dumps({
            "matches": rec.get("matches") or [],
            "refs": rec.get("refs") or [],
            "vendor_advisories": rec.get("vendor_advisories") or {},
            "kev_notes": rec.get("kev_notes") or "",
        }),
    }


def _batches(rows: list, size: int) -> Iterable[list]:
    for start in range(0, len(rows), size):
        yield rows[start:start + size]


# ─── Build (datasets worker) ────────────────────────────────────────────────

def sources_fingerprint(db: Session) -> dict[str, Any]:
    """What the table would be built from now: each feeder's file, with its
    modification time and size (a refresh rewrites the same file)."""
    sources: dict[str, Any] = {}
    for kind in FEEDER_KINDS:
        path = latest_dataset_path(db, kind)
        try:
            st = os.stat(path) if path else None
        except OSError:
            st = None
        sources[kind] = [path, st.st_mtime_ns, st.st_size] if st else None
    return {"version": BUILD_VERSION, "sources": sources}


def _build_info(db: Session) -> dict[str, Any]:
    return get_platform_setting(db, BUILD_KEY, {})


def rebuild_needed(db: Session) -> bool:
    return _build_info(db).get("fingerprint") != sources_fingerprint(db)


def rebuild(db: Session, *, force: bool = False) -> bool:
    """Rebuild the table from the datasets, unless it already reflects them.

    One transaction: pages read the previous table until the commit."""
    fingerprint = sources_fingerprint(db)
    if not force and _build_info(db).get("fingerprint") == fingerprint:
        return False

    raw = {kind: _load_dataset_file(source[0]) if source else None for kind, source in fingerprint["sources"].items()}
    merged, loaded = merge_sources(raw["nvd_cpe_cve"], raw["cisa_kev"], raw["epss"], raw["vendor_advisories"])
    del raw
    vendors: set[str] = set()
    advised = 0
    for rec in merged.values():
        if rec.get("vendor_advisories"):
            advised += 1
            vendors.update(rec["vendor_advisories"].keys())
    rows = [_row(rec) for rec in merged.values()]
    del merged

    try:
        db.execute(delete(T))
        for batch in _batches(rows, _INSERT_BATCH):
            db.execute(insert(T), batch)
        # Commits the rows and the build info together.
        set_platform_setting(db, BUILD_KEY, {
            "fingerprint": fingerprint,
            "built_at": datetime.now(timezone.utc).isoformat(),
            "datasets_loaded": loaded,
            "vendor_advisory_vendors": sorted(vendors),
            "vendor_advisory_cve_count": advised,
        })
    except Exception:
        db.rollback()
        raise
    logger.info("Threat Intel: built — %d CVEs from %s", len(rows), ", ".join(loaded) or "no dataset")
    return True


def queue_rebuild_if_needed(db: Session, redis: Any, enqueue: Callable[[], None]) -> bool:
    """Queue a rebuild when the datasets changed since the table was built
    (scheduler, every minute). A refresh in progress rebuilds at its end."""
    if redis.exists(REFRESH_LOCK_KEY) or not rebuild_needed(db):
        return False
    return request_rebuild(redis, enqueue)


def request_rebuild(redis: Any, enqueue: Callable[[], None]) -> bool:
    """Queue a rebuild, unless one is already queued."""
    if not redis.set(REBUILD_QUEUED_KEY, "1", nx=True, ex=REBUILD_QUEUED_TTL_SECONDS):
        return False
    try:
        enqueue()
    except Exception:
        redis.delete(REBUILD_QUEUED_KEY)
        raise
    return True


# ─── Public API: query, detail, stats ───────────────────────────────────────

_VALID_SORTS = {"threat_score", "cvss", "epss", "kev_due", "kev_added", "published"}


def _score_column(today: date):
    bonus = case(
        *[(T.kev_added >= today - timedelta(days=limit), value) for limit, value in _RECENCY_STEPS],
        else_=0.0,
    )
    return T.base_score + bonus


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def query(
    db: Session,
    *,
    q: str = "",
    severity: list[str] | None = None,
    kev_only: bool = False,
    ransomware_only: bool = False,
    min_epss: float | None = None,
    min_cvss: float | None = None,
    sort: str = "threat_score",
    order: str = "desc",
    page: int = 1,
    per_page: int = 50,
    today: date | None = None,
    fleet_workspace: int | None = None,
    on_fleet_only: bool = False,
) -> dict[str, Any]:
    """``fleet_workspace``: the open client, whose fleet each CVE is
    counted on (``affected``); ``on_fleet_only`` keeps only the CVEs found on
    it (app.threat_intel.exposure)."""
    today = today or date.today()
    score = _score_column(today)
    rows = db.query(
        T.cve, T.summary, T.cvss, T.severity, T.vendor, T.product, T.epss, T.epss_percentile,
        T.kev, T.kev_added, T.kev_due, T.ransomware, T.base_score,
    )

    ql = (q or "").strip()
    if ql:
        pattern = _like(ql)
        rows = rows.filter(or_(*[col.ilike(pattern, escape="\\") for col in (T.cve, T.summary, T.vendor, T.product)]))
    sev_set = sorted({s.lower() for s in (severity or []) if s})
    if sev_set:
        rows = rows.filter(T.severity.in_(sev_set))
    if kev_only:
        rows = rows.filter(T.kev.is_(True))
    if ransomware_only:
        rows = rows.filter(T.ransomware.is_(True))
    if min_epss is not None:
        rows = rows.filter(func.coalesce(T.epss, 0.0) >= min_epss)
    if min_cvss is not None:
        rows = rows.filter(func.coalesce(T.cvss, 0.0) >= min_cvss)
    if on_fleet_only and fleet_workspace is not None:
        rows = rows.filter(T.cve.in_(exposure.fleet_cves(fleet_workspace)))

    total = rows.count()

    if sort not in _VALID_SORTS:
        sort = "threat_score"
    descending = (order or "desc").lower() != "asc"
    if sort in ("kev_due", "kev_added"):
        column = T.kev_due if sort == "kev_due" else T.kev_added
        # Missing dates last, whatever the order.
        key = (column.desc() if descending else column.asc()).nulls_last()
    else:
        column = {"cvss": func.coalesce(T.cvss, 0.0), "epss": func.coalesce(T.epss, 0.0)}.get(sort, score)
        key = column.desc() if descending else column.asc()

    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    page_rows = rows.order_by(key, T.cve.asc()).offset((page - 1) * per_page).limit(per_page).all()
    cves = [_summarise(r, today) for r in page_rows]
    if fleet_workspace is not None:
        counts = exposure.affected_counts(db, fleet_workspace, [c["cve"] for c in cves])
        for c in cves:
            c["affected"] = counts.get(c["cve"], 0)

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, -(-total // per_page)),
        "cves": cves,
    }


def _iso(d: date | None) -> str | None:
    return d.isoformat() if d else None


def _summarise(r: Any, today: date) -> dict:
    """Compact row used in list responses."""
    return {
        "cve":               r.cve,
        "summary":           (r.summary or "")[:240],
        "cvss":              r.cvss,
        "severity":          r.severity,
        "vendor":            r.vendor,
        "product":           r.product,
        "epss":              r.epss,
        "epss_percentile":   r.epss_percentile,
        "kev":               r.kev,
        "kev_added":         _iso(r.kev_added),
        "kev_due":           _iso(r.kev_due),
        "ransomware":        r.ransomware,
        "threat_score":      _threat_score(r.base_score, r.kev_added, today),
    }


def detail(db: Session, cve_id: str, today: date | None = None) -> dict[str, Any] | None:
    rec = db.get(T, (cve_id or "").strip().upper())
    if rec is None:
        return None
    try:
        details = json.loads(rec.details_json or "{}")
    except ValueError:
        details = {}
    out = _summarise(rec, today or date.today())
    out["summary"] = rec.summary or ""
    out.update({
        "matches": details.get("matches") or [],
        "refs": details.get("refs") or [],
        "vendor_advisories": details.get("vendor_advisories") or {},
        "kev_notes": details.get("kev_notes") or "",
    })
    return out


def stats(db: Session, today: date | None = None) -> dict[str, Any]:
    today = today or date.today()
    week_ago, in_a_week = today - timedelta(days=7), today + timedelta(days=7)

    def count(condition):
        return func.coalesce(func.sum(case((condition, 1), else_=0)), 0)

    row = db.query(
        func.count(T.cve),
        count(T.kev.is_(True)),
        count(T.kev.is_(True) & (T.kev_due >= today) & (T.kev_due <= in_a_week)),
        count(T.ransomware.is_(True)),
        count(T.kev.is_(True) & (T.kev_added >= week_ago) & (T.kev_added <= today)),
        count(T.epss >= 0.5),
        count(T.severity == "critical"),
        count(T.severity == "high"),
    ).one()
    info = _build_info(db)
    return {
        "total_cves": int(row[0]),
        "kev_count": int(row[1]),
        "kev_due_within_7d": int(row[2]),
        "ransomware_count": int(row[3]),
        "new_kev_7d": int(row[4]),
        "high_epss_count": int(row[5]),
        "critical_count": int(row[6]),
        "high_count": int(row[7]),
        "datasets_loaded": info.get("datasets_loaded", []),
        "vendor_advisory_vendors": info.get("vendor_advisory_vendors", []),
        "vendor_advisory_cve_count": info.get("vendor_advisory_cve_count", 0),
        "built_at": info.get("built_at"),
    }
