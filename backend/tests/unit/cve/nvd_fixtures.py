"""NVD API 2.0 entries, shaped like the real responses (trimmed)."""


def nvd_entry(cve_id, *, matches=(), cvss=None, cvss_type="Primary", severity=None, modified="2026-11-01T10:00:00.000",
              description="A vulnerability.", nested=False, metric="cvssMetricV31"):
    metrics = {}
    if cvss is not None:
        metrics[metric] = [{"source": "nvd@nist.gov", "type": cvss_type,
                            "cvssData": {"baseScore": cvss, **({"baseSeverity": severity} if severity else {})}}]
    cpe_nodes = [{"operator": "OR", "negate": False, "cpeMatch": list(matches)}]
    if nested:
        cpe_nodes = [{"operator": "AND", "children": cpe_nodes}]
    return {"cve": {
        "id": cve_id,
        "published": "2026-10-01T08:00:00.000",
        "lastModified": modified,
        "descriptions": [{"lang": "es", "value": "Una vulnerabilidad."}, {"lang": "en", "value": description}],
        "metrics": metrics,
        "configurations": [{"nodes": cpe_nodes}],
        "references": [{"url": f"https://example.org/{cve_id}"}],
    }}


def cpe_match(vendor, product, version="*", vulnerable=True, **bounds):
    return {"vulnerable": vulnerable, "criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*", **bounds}


def page(entries, start_index=0, total=None):
    return {"startIndex": start_index, "resultsPerPage": len(entries),
            "totalResults": len(entries) if total is None else total, "vulnerabilities": list(entries)}
