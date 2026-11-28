"""
CVE identifiers named by a finding: what links a finding to the Threat Intel
catalog ("present on my fleet", affected assets of a CVE).
"""
from __future__ import annotations

import re
from collections.abc import Iterable

# "CVE-2024-1234" but not inside a longer token ("XCVE-…", "CVE-2024-12345"
# is read whole, never as CVE-2024-1234).
_CVE_ID = re.compile(r"(?<![\w-])CVE-\d{4}-\d{4,}(?!\d)", re.IGNORECASE)
MAX_ID_LENGTH = 32  # threat_intel_cves.cve, finding_cves.cve


def cve_ids_in(*texts: str | None) -> set[str]:
    """Every CVE id in the texts, upper-cased."""
    found: set[str] = set()
    for text in texts:
        if text:
            found.update(m.upper() for m in _CVE_ID.findall(text))
    return {cve for cve in found if len(cve) <= MAX_ID_LENGTH}


def finding_cve_ids(
    *,
    cve: str | None,
    cves: Iterable[str] = (),
    title: str = "",
    description: str = "",
    evidence: str = "",
    references: Iterable[str] = (),
) -> tuple[str, ...]:
    """The CVEs a finding is about: the ones its plugin names (``cve``, and
    ``cves`` when it is about several, like an inventory product listing
    them all) and the ones its text cites. Sorted, for stable storage."""
    found = cve_ids_in(cve, *cves, title, description, evidence, *references)
    return tuple(sorted(found))
