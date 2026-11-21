import pytest

from app.cve.cpe import Cpe, CpeMatch, VersionRange

OPENSSH = "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"


def test_un_nom_cpe_est_decompose_en_type_editeur_produit_version():
    cpe = Cpe.parse("cpe:2.3:o:Linux:Linux_Kernel:6.1.0:*:*:*:*:*:*:*")

    assert (cpe.part, cpe.vendor, cpe.product, cpe.version) == ("o", "linux", "linux_kernel", "6.1.0")


@pytest.mark.parametrize("raw", [None, "", "openssh 9.6", "cpe:2.3:a::openssh:9.6", "cpe:2.3:a:openbsd"])
def test_un_texte_qui_n_est_pas_un_cpe_est_ignore(raw):
    assert Cpe.parse(raw) is None


def test_un_cpe_se_reecrit_sous_sa_forme_canonique():
    assert str(Cpe.parse(OPENSSH)) == OPENSSH


def test_deux_cpe_du_meme_produit_sont_comparables_meme_si_leur_type_differe():
    application = Cpe.parse("cpe:2.3:a:linux:linux_kernel:6.1:*:*:*:*:*:*:*")
    os_component = Cpe.parse("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*")

    assert application.same_product(os_component)


@pytest.mark.parametrize(("alias", "canonical"), [("f5", "nginx"), ("sun", "oracle"), ("pivotal_software", "vmware")])
def test_un_editeur_rachete_est_reconnu_sous_ses_deux_noms(alias, canonical):
    # Régression : "oracle"->"sun" et "sun"->"oracle" se croisaient et ne
    # correspondaient jamais l'un à l'autre.
    product = "jdk" if canonical == "oracle" else "nginx" if canonical == "nginx" else "spring_boot"
    old = Cpe.parse(f"cpe:2.3:a:{alias}:{product}:1.0:*:*:*:*:*:*:*")
    new = Cpe.parse(f"cpe:2.3:a:{canonical}:{product}:1.0:*:*:*:*:*:*:*")

    assert old.same_product(new)


def test_deux_produits_differents_ne_sont_pas_comparables():
    assert not Cpe.parse(OPENSSH).same_product(Cpe.parse("cpe:2.3:a:openbsd:openbgpd:9.6:*:*:*:*:*:*:*"))


@pytest.mark.parametrize(
    ("bounds", "installed", "vulnerable"),
    [
        ({"versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}, "2.4.49", True),
        ({"versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}, "2.4.50", False),
        ({"versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}, "2.3.9", False),
        ({"versionEndIncluding": "1.2.3"}, "1.2.3", True),
        ({"versionStartExcluding": "1.0"}, "1.0", False),
        ({"versionEndExcluding": "9.8"}, None, False),
        ({"versionEndExcluding": "9.8"}, "pas-une-version", False),
        ({}, None, True),
    ],
)
def test_une_version_est_vulnerable_si_elle_est_dans_la_plage(bounds, installed, vulnerable):
    assert VersionRange.from_nvd(bounds).contains(installed) is vulnerable


@pytest.mark.parametrize(
    ("bounds", "text"),
    [
        ({"versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}, ">= 2.4.0 and < 2.4.50"),
        ({"versionEndIncluding": "1.2"}, "<= 1.2"),
        ({}, "all versions"),
    ],
)
def test_une_plage_de_versions_se_decrit_lisiblement(bounds, text):
    assert VersionRange.from_nvd(bounds).describe() == text


def test_une_configuration_sans_plage_ni_version_touche_toutes_les_versions():
    match = CpeMatch.from_nvd({"cpe23": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"})

    assert match.affects(Cpe.parse(OPENSSH), "9.6")


def test_une_configuration_sur_une_version_precise_ne_touche_que_cette_version():
    # Régression : sans plage, n'importe quelle version d'Apache était déclarée
    # vulnérable à une CVE qui ne vise que la 2.4.49.
    match = CpeMatch.from_nvd({"cpe23": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"})
    apache = Cpe.parse("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")

    assert match.affects(apache, "2.4.49")
    assert not match.affects(apache, "2.4.58")


def test_une_version_non_standard_est_comparee_comme_du_texte():
    match = CpeMatch.from_nvd({"cpe23": "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"})

    assert match.affects(Cpe.parse(OPENSSH), "8.9P1")
    assert not match.affects(Cpe.parse(OPENSSH), "9.6p1")


def test_une_configuration_au_format_api_nvd_2_est_lue():
    match = CpeMatch.from_nvd({"criteria": OPENSSH, "versionEndExcluding": "9.8"})

    assert match.versions.end_excluding == "9.8"
