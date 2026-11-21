import pytest

from app.cve.version_cmp import parse


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("9.6", "9.6p1"),  # OpenSSH portable
        ("9.6p1", "9.6p2"),
        ("9.6p1", "9.7"),
        ("8.9p1", "9.0p1"),
        ("1.1.1v", "1.1.1w"),  # OpenSSL letter releases
        ("1.1.1", "1.1.1a"),
        ("1.0.2z", "1.0.2za"),
        ("1.0.2za", "1.0.2zb"),
        ("2.4.49", "2.4.50"),
    ],
)
def test_les_schemas_de_version_d_openssh_et_d_openssl_sont_ordonnes(lower, higher):
    assert parse(lower) < parse(higher)


@pytest.mark.parametrize("raw", ["9.6p1", "1.1.1w", "1:2.30", "2.4.49"])
def test_les_versions_courantes_sont_lisibles(raw):
    assert parse(raw) is not None


def test_une_version_de_paquet_brute_doit_etre_nettoyee_par_l_appelant():
    # Le suffixe de distribution ("-0ubuntu0.20.04.1") est retiré par
    # pkg_to_cpe avant comparaison ; brut, il n'est pas comparable.
    assert parse("1:2.30-0ubuntu0.20.04.1") is None


def test_le_suffixe_openssh_est_insensible_a_la_casse():
    assert parse("8.9P1") == parse("8.9p1")


@pytest.mark.parametrize("raw", ["", None, "latest", "abc.def"])
def test_une_version_illisible_ne_donne_rien(raw):
    assert parse(raw) is None
