import pytest

from app.scanner.allowlist import AllowlistPolicy
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
