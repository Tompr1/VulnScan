"""
RQ worker tasks.

This module is the composition root of the background jobs: it wires the
production collaborators (database, Redis, Neo4j, notifiers) into the use
cases and exposes them as plain functions that RQ can import by path.
"""
import os
import http.client
import json
import logging
from datetime import datetime, timezone
from functools import partial

from redis import Redis

from sqlalchemy.orm import Session

from app.compliance.mapper import map_compliance_by_cve_or_category
from app.core.config import settings
from app.core.job_queue import CVE_CATALOG_SYNC_TIMEOUT, get_job_queue
from app.cve.nvd_sync import HttpNvdFeed, NvdCatalogSync
from app.cve.sql_catalog import SqlCveCatalog, SqlSyncStateStore
from app.cve.enricher import CveSeverityEnricher
from app.db import models
from app.db.session import SessionLocal
from app.inventory.audit.auditor import DeviceAuditor
from app.inventory.audit.catalog import EndOfLifeDateCatalog
from app.inventory.audit.rules import default_rules
from app.inventory.audit.service import InventoryAudit
from app.inventory.collector import InventoryCollector
from app.inventory.repository import SqlInventoryRepository
from app.risk.risk_engine import parse_criticality
from app.scan_jobs.ai_trigger import SqlAutoAnalysisTrigger
from app.scan_jobs.executors import default_executors
from app.scan_jobs.filtering import FindingFilterPolicy
from app.scan_jobs.graph import open_finding_graph
from app.scan_jobs.notifications import ScanNotifier
from app.scan_jobs.processing import FindingProcessor
from app.scan_jobs.repository import ScanJobSnapshot, SqlIntegrationSource, SqlScanJobRepository
from app.scan_jobs.runner import ScanJobRunner
from app.scanner.engine import default_engine
from app.scanner.profile import ScanProfile

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("vulnscan.worker")

_CVE_DATA_DIR = os.environ.get("CVE_DATA_DIR", "/app/data/cve")
_CVE_SYNC_LOCK = "cve_catalog_sync_lock"


def run_scan_job(job_id: int) -> None:
    """RQ task — runs one scan job end to end."""
    build_scan_job_runner().run(job_id)


def run_cve_catalog_sync() -> None:
    """RQ task — imports, then keeps up to date, the NVD catalog in Postgres.

    A run stops by itself when its time budget is used and saves its
    progress; it then re-queues itself, so the multi-hour first import goes
    through without anyone pressing a button. A failure (NVD down…) raises,
    and is retried at the next scheduled dataset refresh.
    """
    redis = Redis.from_url(settings.REDIS_URL)
    if not redis.set(_CVE_SYNC_LOCK, "1", nx=True, ex=CVE_CATALOG_SYNC_TIMEOUT):
        logger.info("NVD catalog sync already running — skipped")
        return
    try:
        report = build_cve_catalog_sync().run()
    finally:
        redis.delete(_CVE_SYNC_LOCK)
    logger.info(
        "NVD catalog sync (%s): %s — %d pages, %d CVEs, %d skipped. %s",
        report.mode, "complete" if report.complete else "partial",
        report.pages, report.cves, report.skipped, report.message,
    )
    if not report.complete:
        get_job_queue().enqueue_cve_catalog_sync()


def build_cve_catalog_sync() -> NvdCatalogSync:
    api_key = os.environ.get("NVD_API_KEY", "")
    catalog = SqlCveCatalog(SessionLocal)
    return NvdCatalogSync(
        feed=HttpNvdFeed(
            lambda url, headers: _ds_fetch_url_retry(url, dict(headers), _NVD_PAGE_TIMEOUT, label="NVD catalog"),
            api_key or None,
        ),
        store=catalog,
        states=SqlSyncStateStore(SessionLocal),
        page_size=_NVD_PAGE_SIZE,
        budget_seconds=CVE_CATALOG_SYNC_TIMEOUT - 600,
        # NVD rate limits: 50 requests / 30 s with a key, 5 / 30 s without.
        pause=lambda: time.sleep(0.6 if api_key else 6.0),
    )


def build_scan_job_runner() -> ScanJobRunner:
    repository = SqlScanJobRepository(SessionLocal)
    return ScanJobRunner(
        repository=repository,
        executors=default_executors(default_engine, lambda: InventoryCollector(SessionLocal), build_inventory_audit),
        processor_factory=partial(_build_finding_processor, repository, _open_cvss_enricher()),
        notifier=ScanNotifier(SqlIntegrationSource(SessionLocal)),
        graph_factory=open_finding_graph,
        ai_trigger=SqlAutoAnalysisTrigger(SessionLocal, get_job_queue(), settings.available_ai_providers),
    )


def build_inventory_audit() -> InventoryAudit:
    return InventoryAudit(SqlInventoryRepository(SessionLocal), DeviceAuditor(default_rules(), EndOfLifeDateCatalog))


def _build_finding_processor(
    repository: SqlScanJobRepository,
    cvss_enricher: CveSeverityEnricher | None,
    job: ScanJobSnapshot,
    profile: ScanProfile,
) -> FindingProcessor:
    asset_options = profile.options.get("asset")
    criticality = asset_options.get("criticality") if isinstance(asset_options, dict) else None
    compliance_rows = repository.compliance_rows(job.workspace_id)
    return FindingProcessor(
        filter_policy=FindingFilterPolicy.from_profile_options(profile.options),
        compliance_mapper=lambda cve, plugin_id: map_compliance_by_cve_or_category(cve, plugin_id, compliance_rows),
        criticality=parse_criticality(criticality),
        cvss_enricher=cvss_enricher,
    )


def _open_cvss_enricher() -> CveSeverityEnricher | None:
    """Multi-source CVSS enricher (NVD + CVEDetails), optional."""
    try:
        return CveSeverityEnricher(_CVE_DATA_DIR)
    except Exception as exc:  # datasets may be missing: scoring falls back to NVD only
        logger.warning("CVE enricher init failed: %s (using NVD only)", exc)
        return None


# ── Dataset Refresh Task ────────────────────────────────────────────────────

import subprocess
import sys
import gzip
import urllib.request
import urllib.error
import concurrent.futures
import threading
import time

_DS_KINDS_ORDER = ["nvd_cpe_cve", "cisa_kev", "epss", "vendor_advisories", "cvedetails_cvss", "cms_cve_map", "compliance_map"]
_DS_KIND_DEPENDS = {"cms_cve_map": "nvd_cpe_cve", "cvedetails_cvss": "nvd_cpe_cve"}
_DS_KIND_NAMES = {
    "nvd_cpe_cve": "nvd_auto", "cisa_kev": "kev_auto", "epss": "epss_auto",
    "vendor_advisories": "vendor_adv_auto",
    "cms_cve_map": "cms_auto", "compliance_map": "compliance_auto", "cvedetails_cvss": "cvedetails_auto",
}
_DS_CANONICAL = {
    "nvd_cpe_cve": "/data/cve/nvd_cpe_cve.json",
    "cisa_kev": "/data/cve/cisa_kev.json",
    "epss": "/data/cve/epss.json",
    "vendor_advisories": "/data/cve/vendor_advisories.json",
    "cvedetails_cvss": "/data/cve/cvedetails_cvss.json",
    "cms_cve_map": "/data/cve/cms_cve_map.json",
    "compliance_map": "/data/cve/compliance_map.json",
}

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD can no longer serve resultsPerPage=2000 within any sane timeout: measured
# from this host, a 2000-item page did not complete in 155s while a 200-item
# page took 9.8s. Smaller pages mean more requests, but they are the only size
# that finishes.
_NVD_PAGE_SIZE = int(os.environ.get("NVD_PAGE_SIZE", "200"))
_NVD_PAGE_TIMEOUT = int(os.environ.get("NVD_PAGE_TIMEOUT", "120"))
# How long a half-finished run stays resumable before its window is
# treated as too stale to keep extending.
_NVD_RESUME_MAX_AGE_HOURS = int(os.environ.get("NVD_RESUME_MAX_AGE_HOURS", "48"))
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_CVEORG_API = "https://cveawg.mitre.org/api/cve"


def _ds_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _ds_fetch_url(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# HTTP status codes worth retrying (transient server errors)
_RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}

# Transport-level failures worth retrying. http.client.HTTPException is the one
# that is easy to miss: IncompleteRead (the connection drops mid-body) derives
# from it, NOT from URLError/OSError, so it used to escape the retry loop
# entirely and fail the page on its first attempt — while the caller still
# logged "failed after retries".
_RETRYABLE_EXC = (
    urllib.error.URLError,
    TimeoutError,
    OSError,
    http.client.HTTPException,
)


def _ds_fetch_url_retry(url, headers=None, timeout=30, max_retries=3, label=""):
    """Fetch URL with exponential backoff retry for transient errors."""
    last_exc = None
    for attempt in range(1, max_retries + 2):  # attempt 1 = initial, 2..4 = retries
        try:
            return _ds_fetch_url(url, headers, timeout)
        except urllib.error.HTTPError as e:
            last_exc = e
            if e.code in _RETRYABLE_HTTP_CODES and attempt <= max_retries:
                delay = 10 * (2 ** (attempt - 1))  # 10s, 20s, 40s
                logger.warning("  %s: HTTP %d, retry %d/%d in %ds...",
                               label, e.code, attempt, max_retries, delay)
                time.sleep(delay)
                continue
            raise  # non-retryable (e.g. 403) or retries exhausted
        except _RETRYABLE_EXC as e:
            last_exc = e
            if attempt <= max_retries:
                delay = 10 * (2 ** (attempt - 1))
                logger.warning("  %s: %s, retry %d/%d in %ds...",
                               label, e, attempt, max_retries, delay)
                time.sleep(delay)
                continue
            raise
    raise last_exc  # should not reach here, but just in case


def _ds_run_script(name, args, timeout=180):
    script = f"/scripts/{name}"
    if not os.path.exists(script):
        return False, f"Script not found: {script}"
    try:
        r = subprocess.run([sys.executable, script] + args, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return False, (r.stderr.strip()[:500] or "non-zero exit")
        return True, ""
    except Exception as e:
        return False, str(e)


def _ds_refresh_nvd(api_key, nvd_days=120):
    """Fetch the NVD CVE feed, resuming an interrupted run.

    NVD throttles sustained paging hard and unpredictably — measured here at
    7.9s per page at the start of a run and ~56s after twenty minutes — so a
    full fetch can outlast the RQ job timeout no matter how that timeout is
    tuned. Rather than guess at their limits, each page is written to disk the
    moment it arrives and a manifest records which query it belongs to. A run
    that is cut short resumes from the first missing page instead of starting
    over, so the refresh completes across however many attempts it takes.
    """
    from pathlib import Path
    raw_dir = Path("/data/raw/nvd")
    out_dir = Path("/data/cve")
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = raw_dir / "_manifest.json"

    size = _NVD_PAGE_SIZE
    rate_delay = 0.6 if api_key else 6.0
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    def _page_file(n):
        return raw_dir / f"nvd_api_page_{n}.json"

    def _page_ok(n):
        """Done only if the page is on disk and parses."""
        f = _page_file(n)
        if not f.exists():
            return False
        try:
            with open(f) as fh:
                json.load(fh)
            return True
        except Exception:
            return False

    def _discard_all():
        for stale in raw_dir.glob("nvd_api_page_*.json"):
            try:
                stale.unlink()
            except Exception as e:
                logger.debug("Could not remove stale raw page %s: %s", stale.name, e)

    # ── Resume, or open a fresh window ───────────────────────────────────
    # A resumed run must reuse the *same* pubStartDate/pubEndDate: they move
    # with wall-clock time, and mixing windows would change what page N means.
    manifest = None
    if manifest_path.exists():
        try:
            with open(manifest_path) as fh:
                m = json.load(fh)
            age_h = (time.time() - m.get("created_ts", 0)) / 3600
            if m.get("page_size") == size and age_h < _NVD_RESUME_MAX_AGE_HOURS:
                manifest = m
                logger.info("NVD: resuming run from %.1fh ago (window %s..%s, %d pages of %d)",
                            age_h, m["start_date"][:10], m["end_date"][:10],
                            m["expected_pages"], size)
            else:
                logger.info("NVD: discarding previous run (age %.1fh, page_size %s) — starting fresh",
                            age_h, m.get("page_size"))
        except Exception as e:
            logger.warning("NVD: unreadable manifest, starting fresh: %s", e)

    if manifest is None:
        _discard_all()
        end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        start_date = (datetime.now(timezone.utc) - __import__("datetime").timedelta(days=nvd_days)).strftime("%Y-%m-%dT%H:%M:%S.000")
        try:
            url = f"{_NVD_API_BASE}?pubStartDate={start_date}&pubEndDate={end_date}&startIndex=0&resultsPerPage={size}"
            first = json.loads(_ds_fetch_url_retry(url, headers, _NVD_PAGE_TIMEOUT, label="NVD page 1"))
        except Exception as e:
            return False, None, f"NVD first page failed: {e}"
        total = first.get("totalResults", 0)
        expected_pages = (total + size - 1) // size if total else 1
        with open(_page_file(1), "w") as fh:
            json.dump(first, fh)
        manifest = {
            "created_ts": time.time(),
            "start_date": start_date,
            "end_date": end_date,
            "page_size": size,
            "total": total,
            "expected_pages": expected_pages,
        }
        with open(manifest_path, "w") as fh:
            json.dump(manifest, fh)
        logger.info("NVD total: %d CVEs, %d pages of %d", total, expected_pages, size)

    start_date = manifest["start_date"]
    end_date = manifest["end_date"]
    total = manifest["total"]
    expected_pages = manifest["expected_pages"]

    # ── Fetch whatever is still missing ──────────────────────────────────
    missing = [n for n in range(1, expected_pages + 1) if not _page_ok(n)]
    if missing:
        logger.info("NVD: %d/%d pages already on disk, fetching %d more",
                    expected_pages - len(missing), expected_pages, len(missing))

    for page_num in missing:
        time.sleep(rate_delay)
        start_idx = (page_num - 1) * size
        try:
            url = f"{_NVD_API_BASE}?pubStartDate={start_date}&pubEndDate={end_date}&startIndex={start_idx}&resultsPerPage={size}"
            page = json.loads(_ds_fetch_url_retry(url, headers, _NVD_PAGE_TIMEOUT, label=f"NVD page {page_num}"))
            # Written via a temp file so a kill mid-write cannot leave a
            # truncated page that later looks complete.
            tmp = _page_file(page_num).with_suffix(".tmp")
            with open(tmp, "w") as fh:
                json.dump(page, fh)
            tmp.replace(_page_file(page_num))
            logger.info("  NVD page %d/%d: startIndex=%d, got %d",
                        page_num, expected_pages, start_idx, len(page.get("vulnerabilities", [])))
        except Exception as e:
            logger.warning("  NVD page %d/%d (startIndex=%d) failed: %s",
                           page_num, expected_pages, start_idx, e)

    # ── Build the dataset only when every page is present ────────────────
    still_missing = [n for n in range(1, expected_pages + 1) if not _page_ok(n)]
    if still_missing:
        have = expected_pages - len(still_missing)
        return False, None, (
            f"NVD refresh incomplete: {have}/{expected_pages} pages fetched. "
            f"Progress is saved — run the refresh again to continue from page "
            f"{still_missing[0]}. Dataset left unchanged."
        )

    pages = []
    for n in range(1, expected_pages + 1):
        with open(_page_file(n)) as fh:
            pages.append(json.load(fh))
    fetched = sum(len(p.get("vulnerabilities", [])) for p in pages)
    if total and fetched < total:
        return False, None, (
            f"NVD refresh incomplete: {fetched} of {total} CVEs across "
            f"{expected_pages} complete pages — NVD may have changed its "
            f"pagination. Dataset left unchanged."
        )
    logger.info("NVD fetch complete: %d/%d CVEs across %d pages", fetched, total, expected_pages)

    inputs = [str(_page_file(n)) for n in range(1, expected_pages + 1)]
    out_path = str(out_dir / f"nvd_cpe_cve_{_ds_ts()}.json")
    ok, err = _ds_run_script("nvd_flatten.py", ["--inputs"] + inputs + ["--out", out_path])
    if not ok:
        return False, None, f"nvd_flatten.py: {err}"

    # Window consumed; the next run opens a fresh one.
    try:
        manifest_path.unlink()
    except Exception:
        pass
    return True, out_path, None


def _ds_refresh_cisa_kev():
    from pathlib import Path
    raw_dir = Path("/data/raw/cisa")
    out_dir = Path("/data/cve")
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = _ds_fetch_url(_CISA_KEV_URL, timeout=30)
        raw_path = str(raw_dir / "known_exploited_vulnerabilities.json")
        with open(raw_path, "wb") as f:
            f.write(data)
    except Exception as e:
        return False, None, f"CISA KEV fetch: {e}"

    out_path = str(out_dir / f"cisa_kev_{_ds_ts()}.json")
    ok, err = _ds_run_script("cisa_kev_convert.py", ["--in", raw_path, "--out", out_path])
    if not ok:
        return False, None, f"cisa_kev_convert.py: {err}"
    return True, out_path, None


def _ds_refresh_epss():
    from pathlib import Path
    raw_dir = Path("/data/raw/epss")
    out_dir = Path("/data/cve")
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = _ds_fetch_url(_EPSS_URL, timeout=60)
        csv_data = gzip.decompress(data)
        raw_path = str(raw_dir / "epss_scores-current.csv")
        with open(raw_path, "wb") as f:
            f.write(csv_data)
    except Exception as e:
        return False, None, f"EPSS fetch: {e}"

    out_path = str(out_dir / f"epss_{_ds_ts()}.json")
    ok, err = _ds_run_script("epss_convert.py", ["--in", raw_path, "--out", out_path])
    if not ok:
        return False, None, f"epss_convert.py: {err}"
    return True, out_path, None


def _ds_refresh_cvedetails(nvd_path, on_progress=None):
    import requests as _requests
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)

    if not os.path.exists(nvd_path):
        return False, None, f"NVD file not found: {nvd_path}"

    with open(nvd_path) as f:
        cve_ids = [e["cve"] for e in json.load(f) if e.get("cve", "").startswith("CVE-")]

    # Load cache
    cache_path = out_dir / "cvedetails_cvss.json"
    existing = {}
    if cache_path.exists():
        try:
            with open(cache_path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                existing = data
        except Exception:
            pass

    new_ids = [c for c in cve_ids if c not in existing]
    logger.info("CVE.org: %d total, %d new to fetch", len(cve_ids), len(new_ids))

    # Tunable via env: CVEORG_WORKERS (default 5), CVEORG_REQ_PER_SEC (default 5)
    max_workers = int(os.environ.get("CVEORG_WORKERS", "5"))
    req_per_sec = float(os.environ.get("CVEORG_REQ_PER_SEC", "5"))
    logger.info("CVE.org: workers=%d, rate_limit=%.1f req/s", max_workers, req_per_sec)

    # Persistent session — reuses TCP connections (skips TLS handshake per request)
    session = _requests.Session()
    session.headers.update({"Accept": "application/json", "User-Agent": "VulnScan/2.0"})
    adapter = _requests.adapters.HTTPAdapter(pool_connections=max_workers, pool_maxsize=max_workers)
    session.mount("https://", adapter)

    # Rate limiter across all threads to avoid being blocked
    _rate_lock = threading.Lock()
    _rate_interval = 1.0 / req_per_sec
    _last_request_time = [0.0]

    def _rate_wait():
        with _rate_lock:
            now = time.time()
            wait = _rate_interval - (now - _last_request_time[0])
            if wait > 0:
                time.sleep(wait)
            _last_request_time[0] = time.time()

    def _fetch_one(cve_id):
        for attempt in range(3):
            _rate_wait()
            try:
                resp = session.get(f"{_CVEORG_API}/{cve_id}", timeout=15)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 5 * (attempt + 1)))
                    logger.warning("  CVE.org 429 rate-limited, backing off %ds", retry_after)
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                d = resp.json()
                containers = d.get("containers", {})
                cna_score = adp_score = None
                for m in containers.get("cna", {}).get("metrics", []):
                    for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                        v = m.get(k)
                        if v and v.get("baseScore"):
                            cna_score = float(v["baseScore"]); break
                    if cna_score: break
                for adp in containers.get("adp", []):
                    for m in adp.get("metrics", []):
                        for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                            v = m.get(k)
                            if v and v.get("baseScore"):
                                adp_score = float(v["baseScore"]); break
                        if adp_score: break
                    if adp_score: break
                # Extract affected products (vendor, product, version ranges)
                affected = []
                for aff in containers.get("cna", {}).get("affected", []):
                    vendor = (aff.get("vendor") or "").strip().lower()
                    product = (aff.get("product") or "").strip().lower()
                    if not vendor or not product:
                        continue
                    for ver in aff.get("versions", []):
                        entry = {"vendor": vendor, "product": product}
                        if ver.get("lessThan"):
                            entry["lessThan"] = ver["lessThan"]
                        if ver.get("lessThanOrEqual"):
                            entry["lessThanOrEqual"] = ver["lessThanOrEqual"]
                        if ver.get("version") and ver["version"] != "0":
                            entry["versionStart"] = ver["version"]
                        if entry.get("lessThan") or entry.get("lessThanOrEqual"):
                            affected.append(entry)

                result = {}
                if cna_score or adp_score:
                    best = max(filter(None, [cna_score, adp_score]))
                    sev = "critical" if best >= 9 else "high" if best >= 7 else "medium" if best >= 4 else "low" if best > 0 else "info"
                    result = {"cvss": best, "severity": sev, "cna_cvss": cna_score, "adp_cvss": adp_score}
                if affected:
                    result["affected"] = affected
                return cve_id, result if result else None
            except _requests.exceptions.RequestException as e:
                logger.warning("  CVE.org %s attempt %d: %s", cve_id, attempt + 1, e)
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
            except Exception as e:
                logger.warning("  CVE.org %s unexpected error: %s", cve_id, e)
            break
        return cve_id, None

    if new_ids:
        done = 0
        total = len(new_ids)
        batch_size = 500
        if on_progress:
            on_progress(0, total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            for batch_start in range(0, total, batch_size):
                batch = new_ids[batch_start:batch_start + batch_size]
                futures = {pool.submit(_fetch_one, c): c for c in batch}
                for f in concurrent.futures.as_completed(futures):
                    cve_id, r = f.result()
                    if r:
                        existing[cve_id] = r
                    done += 1
                    if done % 100 == 0 or done == total:
                        logger.info("  CVE.org: %d/%d", done, total)
                        if on_progress:
                            on_progress(done, total)
                # Checkpoint after each batch
                try:
                    with open(cache_path, "w") as _cf:
                        json.dump(existing, _cf)
                except Exception:
                    pass

    session.close()

    out_path = str(out_dir / f"cvedetails_cvss_{_ds_ts()}.json")
    with open(out_path, "w") as f:
        json.dump(existing, f)
    return True, out_path, None


def _ds_refresh_cms_cve_map(nvd_path):
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not os.path.exists(nvd_path):
        return False, None, f"NVD file not found: {nvd_path}"
    out_path = str(out_dir / f"cms_cve_map_{_ds_ts()}.json")
    ok, err = _ds_run_script("generate_cms_cve_map.py", ["--nvd", nvd_path, "--out", out_path])
    if not ok:
        return False, None, f"generate_cms_cve_map.py: {err}"
    return True, out_path, None


def _ds_refresh_compliance_map():
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = str(out_dir / f"compliance_map_{_ds_ts()}.json")
    ok, err = _ds_run_script("generate_compliance_map.py", ["--out", out_path])
    if not ok:
        return False, None, f"generate_compliance_map.py: {err}"
    return True, out_path, None


def _ds_refresh_vendor_advisories():
    from pathlib import Path
    out_dir = Path("/data/cve")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = str(out_dir / f"vendor_advisories_{_ds_ts()}.json")
    ok, err = _ds_run_script("vendor_advisories_fetch.py", ["--out", out_path], timeout=900)
    if not ok:
        return False, None, f"vendor_advisories_fetch.py: {err}"
    return True, out_path, None


def run_dataset_refresh(workspace_id: int, kinds: list[str] | None = None) -> None:
    """Background task: fetch/convert/swap datasets from external sources."""
    import redis as _redis

    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    r = _redis.Redis.from_url(redis_url)
    lock_key = f"dataset_refresh_lock:{workspace_id}"
    status_key = f"dataset_refresh:{workspace_id}"

    # TTL must cover the slowest full refresh, or the lock expires mid-run and a
    # scheduled trigger starts a second one. Matches the 7200s job_timeout.
    if not r.set(lock_key, "1", nx=True, ex=7200):
        logger.warning("Dataset refresh already running for workspace %d", workspace_id)
        return

    requested = kinds or list(_DS_KINDS_ORDER)
    ordered = []
    for k in _DS_KINDS_ORDER:
        if k in requested:
            dep = _DS_KIND_DEPENDS.get(k)
            if dep and dep not in ordered and dep not in requested:
                ordered.append(dep)
            if k not in ordered:
                ordered.append(k)

    state = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "kinds": {k: {"status": "pending", "message": ""} for k in ordered},
        "current_kind": None,
        "finished_at": None,
    }
    r.setex(status_key, 3600, json.dumps(state))

    db = SessionLocal()
    api_key = os.environ.get("NVD_API_KEY", "")
    results: dict[str, str] = {}

    def _cveorg_progress(done, total):
        """Push CVE.org fetch progress into Redis so the frontend can display it."""
        state["kinds"]["cvedetails_cvss"]["message"] = f"{done}/{total} CVEs"
        state["kinds"]["cvedetails_cvss"]["progress"] = round(done / total * 100) if total else 0
        try:
            r.setex(status_key, 3600, json.dumps(state))
        except Exception:
            pass

    _dispatch = {
        "nvd_cpe_cve": lambda: _ds_refresh_nvd(api_key),
        "cisa_kev": lambda: _ds_refresh_cisa_kev(),
        "epss": lambda: _ds_refresh_epss(),
        "vendor_advisories": lambda: _ds_refresh_vendor_advisories(),
        "cvedetails_cvss": lambda dep: _ds_refresh_cvedetails(dep, on_progress=_cveorg_progress),
        "cms_cve_map": lambda dep: _ds_refresh_cms_cve_map(dep),
        "compliance_map": lambda: _ds_refresh_compliance_map(),
    }

    try:
        for kind in ordered:
            if not r.exists(lock_key):
                logger.info("Dataset refresh cancelled")
                state["status"] = "cancelled"
                break

            r.expire(lock_key, 3600)
            state["current_kind"] = kind
            state["kinds"][kind]["status"] = "running"
            r.setex(status_key, 3600, json.dumps(state))
            logger.info("Refreshing dataset: %s", kind)

            dep = _DS_KIND_DEPENDS.get(kind)
            dep_path = None
            if dep:
                dep_path = results.get(dep) or "/data/cve/nvd_cpe_cve.json"
                if not os.path.exists(dep_path):
                    state["kinds"][kind] = {"status": "failed", "message": f"Dependency {dep} not available"}
                    r.setex(status_key, 3600, json.dumps(state))
                    continue

            try:
                fn = _dispatch[kind]
                if dep:
                    success, out, err = fn(dep_path)
                else:
                    success, out, err = fn()
            except Exception as exc:
                success, out, err = False, None, str(exc)

            if success and out:
                # Copy timestamped file → canonical (non-timestamped) file
                canonical = _DS_CANONICAL.get(kind)
                if canonical:
                    import shutil
                    shutil.copy2(out, canonical)
                    logger.info("  %s: copied %s -> %s", kind, out, canonical)
                # DB record points to canonical path (stable, won't break if timestamped backup is deleted)
                _swap_dataset(workspace_id, kind, canonical or out, db)
                results[kind] = canonical or out
                state["kinds"][kind] = {"status": "done", "message": ""}
                logger.info("  %s: done -> %s", kind, canonical or out)
            else:
                state["kinds"][kind] = {"status": "failed", "message": err or "Unknown error"}
                logger.error("  %s: failed — %s", kind, err)

            r.setex(status_key, 3600, json.dumps(state))

        done_count = sum(1 for v in state["kinds"].values() if v["status"] == "done")
        fail_count = sum(1 for v in state["kinds"].values() if v["status"] == "failed")
        if state["status"] != "cancelled":
            state["status"] = "done" if fail_count == 0 else "partial" if done_count > 0 else "failed"

        # Clean up old timestamped files — keep only canonical files
        if done_count > 0:
            try:
                _cleanup_old_dataset_files()
            except Exception as e:
                logger.warning("Dataset cleanup failed: %s", e)

        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        state["current_kind"] = None
        r.setex(status_key, 3600, json.dumps(state))
        logger.info("Dataset refresh finished: %s", state["status"])

    except Exception as e:
        state["status"] = "failed"
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        state["current_kind"] = None
        r.setex(status_key, 3600, json.dumps(state))
        logger.exception("Dataset refresh crashed: %s", e)
    finally:
        r.delete(lock_key)
        db.close()


def _cleanup_old_dataset_files() -> None:
    """
    Delete old timestamped dataset files from /data/cve/.
    Keeps canonical files and any file still referenced by an enabled DB record.
    """
    import glob
    import re

    data_dir = "/data/cve"
    if not os.path.isdir(data_dir):
        return

    # Canonical filenames — NEVER delete these
    canonical_names = set(os.path.basename(p) for p in _DS_CANONICAL.values())

    # Also protect any file still referenced by an enabled dataset record
    protected = set(canonical_names)
    try:
        db = SessionLocal()
        for ds in db.query(models.CveDataset).filter(models.CveDataset.enabled == True).all():
            if ds.path:
                protected.add(os.path.basename(ds.path))
        db.close()
    except Exception as e:
        logger.warning("Cleanup: could not query DB for protected files, skipping: %s", e)
        return

    # Only match timestamped files: kind_YYYYMMDD_HHMMSS.json
    _TS_PATTERN = re.compile(r"^(.+)_\d{8}_\d{6}\.json$")

    removed = 0
    for filepath in glob.glob(os.path.join(data_dir, "*.json")):
        filename = os.path.basename(filepath)
        # Never delete canonical or DB-protected files
        if filename in protected:
            continue
        # Only delete files matching the timestamped pattern
        m = _TS_PATTERN.match(filename)
        if not m or m.group(1) not in _DS_CANONICAL:
            continue
        try:
            os.remove(filepath)
            removed += 1
            logger.info("  Cleanup: removed old dataset file %s", filename)
        except OSError as e:
            logger.warning("  Cleanup: failed to remove %s: %s", filename, e)

    if removed:
        logger.info("Dataset cleanup: removed %d old timestamped file(s)", removed)


def _swap_dataset(ws_id: int, kind: str, new_file_path: str, db: Session) -> None:
    """Atomically swap: create new dataset, disable old ones of same kind."""
    try:
        # Verify the new file exists and is non-empty before disabling the old one
        if not os.path.isfile(new_file_path):
            raise FileNotFoundError(f"New dataset file not found: {new_file_path}")
        if os.path.getsize(new_file_path) < 10:
            raise ValueError(f"New dataset file is empty or too small: {new_file_path}")

        db.query(models.CveDataset).filter(
            models.CveDataset.workspace_id == ws_id,
            models.CveDataset.kind == kind,
            models.CveDataset.enabled == True,
        ).update({"enabled": False})

        name = _DS_KIND_NAMES.get(kind, kind)
        new_ds = models.CveDataset(
            workspace_id=ws_id,
            name=name,
            kind=kind,
            path=new_file_path,
            enabled=True,
        )
        db.add(new_ds)
        db.commit()
        logger.info("Swapped dataset %s: new ID=%d", kind, new_ds.id)

        # Invalidate the Threat Intel cache for this workspace if a feeder
        # dataset was just rotated. Best-effort — never block the swap on it.
        if kind in ("nvd_cpe_cve", "cisa_kev", "epss", "vendor_advisories"):
            try:
                from app.threat_intel import aggregator as _ti
                _ti.invalidate(ws_id)
            except Exception as _ti_err:
                logger.debug("Threat Intel cache invalidation skipped: %s", _ti_err)
    except Exception as e:
        db.rollback()
        logger.error("Failed to swap dataset %s: %s", kind, e)
        raise


# ── AI Analysis Tasks ─────────────────────────────────────────────────────

def run_ai_analysis(analysis_id: int) -> None:
    """RQ task — runs AI deep analysis on scan findings."""
    from app.ai.engine import run_analysis
    run_analysis(analysis_id)


def run_ai_poc(analysis_id: int, finding_id: int) -> None:
    """RQ task — generates PoC for a single finding."""
    from app.ai.engine import generate_poc
    generate_poc(analysis_id, finding_id)

