import pytest

from app.cve.ids import cve_ids_in, finding_cve_ids


def test_les_identifiants_sont_releves_en_majuscules_et_sans_doublon():
    assert cve_ids_in("cve-2024-1234 and CVE-2024-1234, (CVE-2023-44487)") == {"CVE-2024-1234", "CVE-2023-44487"}


@pytest.mark.parametrize("text", ["XCVE-2024-1234", "MY-CVE-2024-1234", "CVE-24-1234", "CVE-2024-123"])
def test_un_faux_identifiant_n_est_pas_releve(text):
    assert cve_ids_in(text) == set()


def test_un_identifiant_long_est_lu_en_entier():
    assert cve_ids_in("CVE-2024-123456") == {"CVE-2024-123456"}


def test_les_cve_d_un_constat_sont_triees():
    assert finding_cve_ids(cve="CVE-2024-0002", cves=["CVE-2024-0001"], title="", references=[None]) == (
        "CVE-2024-0001", "CVE-2024-0002",
    )
