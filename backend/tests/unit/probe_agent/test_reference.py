"""Données de référence sur la sonde : lues sur la plateforme, gardées sur disque."""
import pytest

from app.cve.matcher import ProductCandidate, find_vulnerabilities
from app.cve.cpe import Cpe
from app.probe_agent.platform import PlatformUnavailable
from app.probe_agent.reference import RemoteReferenceData
from tests.fakes import FakePlatform

OPENSSH = {"cve": "CVE-2024-6387", "summary": "s", "severity": "high", "cvss": 8.1, "refs": [],
           "matches": [{"cpe23": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"}]}
NGINX = {"cve": "CVE-2021-23017", "summary": "s", "severity": "high", "cvss": 7.7, "refs": [],
         "matches": [{"cpe23": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.21.0"}]}


def reference(tmp_path, platform):
    data = RemoteReferenceData(platform, tmp_path / "ref")
    data.refresh()
    return data


def test_un_jeu_inchange_est_relu_sur_disque_sans_le_retelecharger(tmp_path):
    platform = FakePlatform(datasets={"cisa_kev": ("v1", [[{"cve": "CVE-2024-1"}]])})
    reference(tmp_path, platform).datasets("cisa_kev")

    contenu = reference(tmp_path, platform).datasets("cisa_kev")

    assert contenu == [[{"cve": "CVE-2024-1"}]]
    assert platform.downloads == ["cisa_kev"]


def test_un_jeu_modifie_sur_la_plateforme_est_retelecharge(tmp_path):
    platform = FakePlatform(datasets={"cisa_kev": ("v1", [[{"cve": "CVE-2024-1"}]])})
    reference(tmp_path, platform).datasets("cisa_kev")
    platform.datasets["cisa_kev"] = ("v2", [[{"cve": "CVE-2024-2"}]])

    assert reference(tmp_path, platform).datasets("cisa_kev") == [[{"cve": "CVE-2024-2"}]]


def test_sans_plateforme_la_copie_locale_sert(tmp_path):
    platform = FakePlatform(datasets={"cisa_kev": ("v1", [[{"cve": "CVE-2024-1"}]])})
    reference(tmp_path, platform).datasets("cisa_kev")
    platform.fail["reference_status"] = [PlatformUnavailable("down")]
    platform.fail["dataset"] = [PlatformUnavailable("down")]

    assert reference(tmp_path, platform).datasets("cisa_kev") == [[{"cve": "CVE-2024-1"}]]


def test_sans_plateforme_ni_copie_locale_le_plugin_le_signale(tmp_path):
    platform = FakePlatform()
    platform.fail["dataset"] = [PlatformUnavailable("down")]

    with pytest.raises(PlatformUnavailable):
        reference(tmp_path, platform).datasets("cisa_kev")


def test_un_nom_de_jeu_ne_sort_pas_du_cache(tmp_path):
    with pytest.raises(ValueError):
        reference(tmp_path, FakePlatform()).datasets("../etc/passwd")


def test_les_cve_d_un_produit_ne_sont_demandees_qu_une_fois_par_job(tmp_path):
    platform = FakePlatform(records=[OPENSSH, NGINX])
    catalog = reference(tmp_path, platform).cve_catalog()

    first = catalog.records_for({("openbsd", "openssh")})
    second = catalog.records_for({("openbsd", "openssh"), ("nginx", "nginx")})  # f5 -> nginx, canonical

    assert [r.cve_id for r in first] == ["CVE-2024-6387"]
    assert {r.cve_id for r in second} == {"CVE-2024-6387", "CVE-2021-23017"}
    assert platform.lookups == [{("openbsd", "openssh")}, {("nginx", "nginx")}]


def test_tant_que_le_catalogue_de_la_plateforme_est_incomplet_le_jeu_nvd_le_complete(tmp_path):
    platform = FakePlatform(catalog_complete=False, datasets={"nvd_cpe_cve": ("n1", [[NGINX]])}, records=[OPENSSH])
    catalog = reference(tmp_path, platform).cve_catalog()
    candidates = [ProductCandidate(Cpe.parse("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"), "9.6", {}),
                  ProductCandidate(Cpe.parse("cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*"), "1.20.0", {})]

    hits = find_vulnerabilities(catalog, candidates)

    assert {h.record.cve_id for h in hits} == {"CVE-2024-6387", "CVE-2021-23017"}
