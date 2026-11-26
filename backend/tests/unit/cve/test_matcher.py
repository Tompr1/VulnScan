from app.cve.cpe import Cpe
from app.cve.matcher import CveRecord, InMemoryCveCatalog, ProductCandidate, find_vulnerabilities
from app.scanner.plugins.cve_packages import match_nvd
from app.scanner.plugins.nvd_match import find_nvd_hits


def nvd_item(cve_id, *matches, cvss=7.5, severity="high"):
    return {"cve": cve_id, "summary": f"{cve_id} summary", "severity": severity, "cvss": cvss,
            "refs": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"], "matches": list(matches)}


def cpe(vendor, product, version="*"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def candidate(vendor, product, version, **context):
    return ProductCandidate(Cpe.parse(cpe(vendor, product, version)), version, context)


CATALOG = InMemoryCveCatalog.from_flattened([
    nvd_item("CVE-2024-6387", {"cpe23": cpe("openbsd", "openssh"), "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"}),
    nvd_item("CVE-2021-41773", {"cpe23": cpe("apache", "http_server", "2.4.49")}),
    nvd_item("CVE-2099-0001"),  # no configuration: never matched
    {"cve": "not-a-cve", "matches": []},
])


def test_le_catalogue_ignore_les_entrees_qui_ne_sont_pas_des_cve():
    assert len(CATALOG) == 3


def test_seules_les_cve_des_produits_demandes_sont_lues():
    records = CATALOG.records_for({("openbsd", "openssh")})

    assert [r.cve_id for r in records] == ["CVE-2024-6387"]


def test_une_version_vulnerable_produit_une_alerte_cve():
    hits = find_vulnerabilities(CATALOG, [candidate("openbsd", "openssh", "9.6")])

    assert [h.record.cve_id for h in hits] == ["CVE-2024-6387"]


def test_une_version_corrigee_ne_produit_aucune_alerte():
    assert find_vulnerabilities(CATALOG, [candidate("openbsd", "openssh", "9.8")]) == []


def test_un_produit_absent_du_catalogue_ne_produit_aucune_alerte():
    assert find_vulnerabilities(CATALOG, [candidate("example", "unknown", "1.0")]) == []


def test_le_contexte_de_l_appelant_est_rendu_avec_l_alerte():
    hit = find_vulnerabilities(CATALOG, [candidate("openbsd", "openssh", "9.6", package="openssh-server")])[0]

    assert hit.candidate.context["package"] == "openssh-server"


def test_une_cve_touchant_plusieurs_produits_installes_ne_signale_que_le_premier_par_configuration():
    catalog = InMemoryCveCatalog([CveRecord.from_flattened(nvd_item("CVE-2023-1", {"cpe23": cpe("acme", "tool")}))])

    hits = find_vulnerabilities(catalog, [candidate("acme", "tool", "1.0"), candidate("acme", "tool", "2.0")])

    assert [h.candidate.version for h in hits] == ["1.0"]


def test_les_alertes_d_empreinte_reseau_conservent_leur_format():
    cands = [{"cpe23": cpe("openbsd", "openssh", "9.6"), "version": "9.6", "confidence": 0.8, "source": "banner"}]

    hit = find_nvd_hits(cands, CATALOG)[0]

    assert hit == {
        "cve": "CVE-2024-6387", "summary": "CVE-2024-6387 summary", "severity": "high", "cvss": 7.5,
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"], "matched_cpe": cpe("openbsd", "openssh", "9.6"),
        "installed_version": "9.6", "confidence": 0.8, "source": "banner", "raw_version": "",
        "versionEndExcluding": "9.8", "versionEndIncluding": None, "version_range": ">= 8.5 and < 9.8",
    }


def test_une_empreinte_reseau_sans_cpe_valide_est_ignoree():
    assert find_nvd_hits([{"cpe23": "nginx 1.18", "version": "1.18"}], CATALOG) == []


def test_un_paquet_installe_vulnerable_est_detecte_une_seule_fois_par_cve():
    items = [nvd_item("CVE-2023-38408", {"cpe23": cpe("openbsd", "openssh"), "versionEndExcluding": "9.3"},
                      {"cpe23": cpe("openbsd", "openssh"), "versionEndExcluding": "9.4"})]

    hits = match_nvd([{"name": "openssh-server", "version": "1:9.2p1-2+deb12u2"}], items)

    assert [(h["cve"], h["package"], h["installed"]) for h in hits] == [("CVE-2023-38408", "openssh-server", "9.2p1")]


def test_un_enregistrement_cve_se_relit_depuis_sa_forme_aplatie():
    for record in CATALOG.records_for({("openbsd", "openssh"), ("apache", "http_server")}):
        assert CveRecord.from_flattened(record.to_flattened()) == record
