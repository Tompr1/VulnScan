from datetime import datetime, timezone

import pytest

from app.cve.nvd import parse_page, parse_vulnerability
from tests.unit.cve.nvd_fixtures import cpe_match, nvd_entry, page


def test_une_cve_nvd_est_lue_avec_son_score_sa_description_anglaise_et_ses_dates():
    cve = parse_vulnerability(nvd_entry("CVE-2024-6387", cvss=8.1, severity="HIGH", description="RCE in sshd"))

    assert (cve.record.cve_id, cve.record.cvss, cve.record.severity, cve.record.summary) == ("CVE-2024-6387", 8.1, "high", "RCE in sshd")
    assert cve.last_modified_at == datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)
    assert cve.record.references == ("https://example.org/CVE-2024-6387",)


def test_le_score_principal_nvd_est_prefere_a_celui_d_un_tiers():
    entry = nvd_entry("CVE-2025-1", cvss=9.8, cvss_type="Primary")
    entry["cve"]["metrics"]["cvssMetricV31"].insert(0, {"type": "Secondary", "cvssData": {"baseScore": 5.0}})

    assert parse_vulnerability(entry).record.cvss == 9.8


def test_une_cve_cvss_4_est_lue():
    assert parse_vulnerability(nvd_entry("CVE-2025-2", cvss=7.0, metric="cvssMetricV40")).record.cvss == 7.0


def test_une_cve_pas_encore_notee_par_nvd_reste_de_severite_moyenne():
    record = parse_vulnerability(nvd_entry("CVE-2026-1")).record

    assert (record.cvss, record.severity) == (None, "medium")


def test_seules_les_configurations_vulnerables_sont_retenues_y_compris_imbriquees():
    entry = nvd_entry(
        "CVE-2026-2",
        nested=True,
        matches=[cpe_match("openbsd", "openssh", versionEndExcluding="9.8"), cpe_match("linux", "linux_kernel", vulnerable=False)],
    )

    matches = parse_vulnerability(entry).record.matches

    assert [(m.cpe.product, m.versions.end_excluding) for m in matches] == [("openssh", "9.8")]


@pytest.mark.parametrize("entry", [{}, {"cve": "x"}, {"cve": {"id": "GHSA-1234"}}, "pas un dict"])
def test_une_entree_malformee_n_est_pas_lue(entry):
    assert parse_vulnerability(entry) is None


def test_une_page_compte_les_entrees_ecartees_et_donne_l_index_suivant():
    parsed = parse_page(page([nvd_entry("CVE-2026-3"), {"cve": {"id": "bad"}}], start_index=400, total=1000))

    assert (len(parsed.cves), parsed.skipped, parsed.next_index, parsed.total_results) == (1, 1, 402, 1000)
