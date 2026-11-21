from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json
from app.cve.cpe import Cpe
from app.cve.matcher import CveCatalog, CveHit, InMemoryCveCatalog, ProductCandidate, find_vulnerabilities
from app.cve.version_cmp import is_likely_patched
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.match.nvd_cpe",
    name="CVE Matching (NVD CPE)",
    category="cve",
    depends_on=["cpe.builder"],
    consumes=["cpe.candidates"],
    provides=["cve.nvd_hits"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

def _component_names(matched_cpe: str) -> tuple[str, str] | None:
    """("Vendor", "Product") for display, from a CPE name."""
    cpe = Cpe.parse(matched_cpe)
    if cpe is None:
        return None
    return cpe.vendor.replace("_", " ").title(), cpe.product.replace("_", " ").title()


def _hit(hit: CveHit) -> dict:
    """Plain-dict view of a hit, published as the cve.nvd_hits artifact."""
    candidate = hit.candidate.context
    record, versions = hit.record, hit.match.versions
    return {
        "cve": record.cve_id,
        "summary": record.summary,
        "severity": record.severity,
        "cvss": record.cvss,
        "refs": list(record.references),
        "matched_cpe": candidate.get("cpe23"),
        "installed_version": candidate.get("version"),
        "confidence": candidate.get("confidence", 0.6),
        "source": candidate.get("source", ""),
        "raw_version": candidate.get("raw_version", ""),
        "versionEndExcluding": versions.end_excluding,
        "versionEndIncluding": versions.end_including,
        "version_range": versions.describe(),
    }


def find_nvd_hits(candidates: list[dict], catalog: CveCatalog) -> list[dict]:
    """CVE hits for the CPE candidates built from the target's fingerprints."""
    products = [
        ProductCandidate(cpe, c.get("version"), c)
        for c in candidates
        if (cpe := Cpe.parse(c.get("cpe23")))
    ]
    return [_hit(h) for h in find_vulnerabilities(catalog, products)]


def _build_remediation(cve: str, h: dict) -> str:
    """Build remediation text for a CVE finding."""
    parts = []

    # Parse affected component
    names = _component_names(h.get("matched_cpe", ""))
    if names:
        vendor, product = names
        version = h.get("installed_version", "unknown")
        parts.append(
            f"[AFFECTED COMPONENT] {vendor} {product} version {version}"
        )

    # Add fix version if available from the match data
    vee = h.get("versionEndExcluding")
    vei = h.get("versionEndIncluding")
    if vee:
        parts.append(f"[FIX] Upgrade to version {vee} or later to resolve this vulnerability.")
    elif vei:
        parts.append(f"[FIX] Upgrade to a version newer than {vei} to resolve this vulnerability.")
    else:
        parts.append("[FIX] Upgrade to the latest patched version from the vendor.")

    # CVE reference
    if cve and cve.startswith("CVE-"):
        parts.append(
            f"[CVE DETAILS] Review {cve} at:\n"
            f"  - https://nvd.nist.gov/vuln/detail/{cve}\n"
            f"  - https://www.cve.org/CVERecord?id={cve}"
        )

    # Severity-based urgency
    severity = h.get("severity", "medium")
    if severity == "critical":
        parts.append("[URGENCY] CRITICAL — Patch immediately within 7 days. Consider temporary mitigations (disable affected feature, block at WAF, network segmentation).")
    elif severity == "high":
        parts.append("[URGENCY] HIGH — Patch within 14 days. Assess exposure and apply compensating controls if immediate patching is not feasible.")
    elif severity == "medium":
        parts.append("[URGENCY] MEDIUM — Plan patching within 30 days during next maintenance window.")

    return "\n\n".join(parts)


class Check(Plugin):
    async def run(self, target, ctx):
        ws_id = ctx.get("workspace_id")
        cands = ctx.get("cpe.candidates", []) or []
        if not cands:
            return PluginResult()

        # Distro-patch awareness: if we have OS info, we can detect backported fixes
        os_info = ctx.get("inventory.os", {}) or {}
        os_id = (os_info.get("os_id") or os_info.get("id") or os_info.get("distro") or "").lower()

        db = SessionLocal()
        try:
            paths = [
                d.path
                for d in db.query(models.CveDataset).filter(
                    models.CveDataset.workspace_id == ws_id,
                    models.CveDataset.kind == "nvd_cpe_cve",
                    models.CveDataset.enabled == True,  # noqa: E712 (SQL expression)
                )
            ]
        finally:
            db.close()
        catalog = InMemoryCveCatalog.from_flattened(item for path in paths for item in (load_json(path) or []))
        hits = find_nvd_hits(cands, catalog)

        findings=[]
        for h in hits[:3000]:
            cve = h.get("cve","CVE")
            fp = stable_fingerprint(target, META.plugin_id, cve, h.get("matched_cpe",""))
            installed = h.get("installed_version", "unknown")
            version_range = h.get("version_range", "all versions")

            # Build detailed description
            vendor_name, product_name = _component_names(h.get("matched_cpe", "")) or ("unknown", "unknown")

            # Check for distro-backported patches on banner/SSH-sourced CPEs
            cpe_source = h.get("source", "")
            raw_ver = h.get("raw_version", "")
            patched = (
                os_id
                and cpe_source in ("ssh", "banner")
                and raw_ver
                and is_likely_patched(raw_ver, os_id)
            )

            if patched:
                v_state = "likely_patched"
                v_method = "distro_backport_detected"
                v_confidence = 0.10
                v_note = (
                    f"The version string ({raw_ver}) contains a distro-specific patch suffix "
                    "indicating a backported security fix. The upstream version may appear "
                    "vulnerable, but the distro vendor has likely applied the relevant patches."
                )
            else:
                v_state = "provisional"
                v_method = "cpe_version_match_only"
                v_confidence = min(h.get("confidence", 0.6), 0.65)
                v_note = (
                    "Based on CPE version matching against NVD. "
                    "Verify the installed version is not patched by the OS vendor."
                )

            description = h.get("summary", "")
            if not description:
                description = f"{cve} affects {vendor_name} {product_name}"
            description += f"\n\nValidation state: {v_state}"
            description += f"\nValidation method: {v_method}"
            description += f"\n{v_note}"
            description += f"\n\nAffected component: {vendor_name} {product_name}"
            description += f"\nInstalled version: {installed}"
            description += f"\nVulnerable range: {version_range}"

            findings.append(Finding(
                severity=h.get("severity","medium"),
                plugin_id=META.plugin_id,
                title=f"Potential {cve}: {vendor_name} {product_name} {installed} (NVD match)",
                description=description,
                references=h.get("refs",[]),
                evidence=(
                    f"cpe={h.get('matched_cpe')} installed={installed} vulnerable_range={version_range} "
                    f"validation_state={v_state} validation_method={v_method}"
                ),
                affected=target,
                fingerprint=fp,
                cvss=h.get("cvss"),
                cve=cve,
                confidence=v_confidence,
                remediation=_build_remediation(cve, h),
            ))
        return PluginResult(findings=findings, artifacts={"cve.nvd_hits": hits})

