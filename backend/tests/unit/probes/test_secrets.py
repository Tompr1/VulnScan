"""Jetons d'enrôlement et secrets des sondes."""
import pytest

from app.probes import secrets


def test_un_secret_est_long_et_jamais_deux_fois_le_meme():
    tirages = {secrets.new_secret() for _ in range(50)}

    assert len(tirages) == 50
    assert all(len(s) >= 43 for s in tirages)


def test_un_secret_correspond_a_son_condense_et_a_lui_seul():
    secret = secrets.new_secret()

    assert secrets.matches(secret, secrets.digest(secret))
    assert not secrets.matches(secret + "x", secrets.digest(secret))
    assert not secrets.matches(secret, None)


def test_l_identifiant_d_une_sonde_se_relit_depuis_l_en_tete():
    header = f"{secrets.SCHEME} {secrets.credential(12, 'abc.def-ghi')}"

    assert secrets.parse_authorization(header) == (12, "abc.def-ghi")


@pytest.mark.parametrize("header", [None, "", "Probe", "Probe 12", "Probe 12.", "Probe .abc", "Probe -1.abc",
                                    "probe 12.abc", "Bearer 12.abc"])
def test_un_en_tete_mal_forme_n_est_pas_lu(header):
    assert secrets.parse_authorization(header) is None
