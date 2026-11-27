import pytest

from app.scanner.allowlist import AllowlistPolicy, parse_entries
from app.scanner.target import ScanTarget, ScanType


def allows(setting: str, target: str, scan_type: ScanType = ScanType.INTERNAL) -> bool:
    return AllowlistPolicy.from_setting(setting).allows(ScanTarget.parse(target), scan_type)


@pytest.mark.parametrize("setting", ["", "*", " , "])
def test_une_allowlist_vide_autorise_toutes_les_cibles(setting):
    assert allows(setting, "203.0.113.7")


def test_une_adresse_dans_un_cidr_autorise_est_scannable():
    assert allows("10.0.0.0/8,192.168.0.0/16", "10.20.30.40")


def test_une_adresse_hors_des_cidr_autorises_est_refusee():
    assert not allows("10.0.0.0/8", "192.168.1.1")


def test_une_adresse_ip_seule_n_autorise_qu_elle_meme():
    assert allows("192.168.1.10", "192.168.1.10")
    assert not allows("192.168.1.10", "192.168.1.11")


@pytest.mark.parametrize("host", ["corp.local", "app.corp.local", "DB.Corp.Local"])
def test_un_suffixe_de_domaine_autorise_le_domaine_et_ses_sous_domaines(host):
    assert allows(".corp.local", host)


def test_un_suffixe_de_domaine_ne_laisse_pas_passer_un_domaine_qui_lui_ressemble():
    assert not allows(".corp.local", "evilcorp.local")


def test_un_domaine_exact_n_autorise_pas_ses_sous_domaines():
    assert allows("exact.com", "exact.com")
    assert not allows("exact.com", "sub.exact.com")


def test_une_entree_ip_n_autorise_pas_un_nom_de_domaine():
    assert not allows("10.0.0.0/8", "intranet.local")


def test_un_scan_externe_n_est_jamais_bloque_par_l_allowlist():
    assert allows("10.0.0.0/8", "public.example.org", ScanType.EXTERNAL)


def test_une_entree_cidr_invalide_est_ignoree_sans_ouvrir_l_allowlist():
    assert not allows("10.0.0.0/33", "10.0.0.1")


def test_l_allowlist_se_decrit_par_ses_entrees():
    assert str(AllowlistPolicy.from_setting("10.0.0.0/8, .Local")) == "10.0.0.0/8,.local"


@pytest.mark.parametrize("setting, network, allowed", [
    ("", "10.0.0.0/8", True),
    ("10.0.0.0/8", "10.20.0.0/16", True),
    ("10.0.0.0/8", "10.0.0.0/8", True),
    ("10.20.0.0/16", "10.0.0.0/8", False),      # plus large que ce qui est permis
    ("10.0.0.0/24,10.0.1.0/24", "10.0.0.0/23", False),  # à cheval : chaque plage doit tenir dans une entrée
    ("10.0.0.5", "10.0.0.5/32", True),
    (".corp.local", "10.0.0.0/24", False),
])
def test_une_plage_a_decouvrir_doit_tenir_dans_une_entree_de_l_allowlist(setting, network, allowed):
    import ipaddress

    assert AllowlistPolicy.from_setting(setting).allows_network(ipaddress.ip_network(network)) is allowed


# ── Une cible telle que saisie ────────────────────────────────────────────

def allows_target(setting: str, raw: str, scan_type: ScanType = ScanType.INTERNAL) -> bool:
    return AllowlistPolicy.from_setting(setting).allows_target(raw, scan_type)


def test_une_plage_doit_tenir_entierement_dans_un_reseau_autorise():
    assert allows_target("192.168.3.0/24", "192.168.3.0/24")
    assert allows_target("192.168.3.0/24", "192.168.3.128/25")
    assert not allows_target("192.168.3.0/24", "192.168.2.0/24")
    assert not allows_target("192.168.3.0/25", "192.168.3.0/24"), "seule sa première adresse est autorisée, pas la plage"


def test_chaque_entree_d_une_liste_doit_etre_autorisee():
    assert allows_target("192.168.3.0/24", "192.168.3.1, 192.168.3.2")
    assert not allows_target("192.168.3.0/24", "192.168.3.1,192.168.2.1")


def test_une_url_ou_un_hote_avec_port_est_juge_sur_son_hote():
    assert allows_target("192.168.3.0/24", "http://192.168.3.7:8080/admin")
    assert allows_target(".corp.local", "nas.corp.local:445")
    assert not allows_target("192.168.3.0/24", "http://192.168.2.7/")


def test_une_cible_externe_n_est_jamais_limitee():
    assert allows_target("192.168.3.0/24", "203.0.113.0/24", ScanType.EXTERNAL)


# ── Entrées saisies par un admin ────────────────────────────────────────────────

def test_les_entrees_sont_separees_par_virgules_et_espaces():
    assert parse_entries(" 192.168.3.0/24, 10.0.0.1  .Corp.Local nas.lan ") == [
        "192.168.3.0/24", "10.0.0.1", ".corp.local", "nas.lan"]


@pytest.mark.parametrize("raw", ["192.168.3.0/33", "300.1.1.1/24", "bad entry!", "*,10.0.0.0/8", "a/b"])
def test_une_entree_inutilisable_est_refusee(raw):
    with pytest.raises(ValueError):
        parse_entries(raw)


def test_une_etoile_seule_autorise_tout():
    assert parse_entries("*") == ["*"]
