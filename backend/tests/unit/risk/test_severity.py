import pytest

from app.risk.severity import Severity


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, Severity.INFO),
        (0.0, Severity.INFO),
        (0.05, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_un_score_est_classe_dans_la_bande_cvss_v3_correspondante(score, expected):
    assert Severity.from_score(score) is expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [("HIGH", Severity.HIGH), ("  Medium ", Severity.MEDIUM), ("info", Severity.INFO)],
)
def test_un_libelle_de_severite_est_reconnu_sans_tenir_compte_de_la_casse(label, expected):
    assert Severity.parse(label) is expected


@pytest.mark.parametrize("label", [None, "", "urgent"])
def test_un_libelle_inconnu_ne_donne_aucune_severite(label):
    assert Severity.parse(label) is None


@pytest.mark.parametrize("severity", list(Severity))
def test_le_score_de_reference_d_une_severite_retombe_dans_sa_propre_bande(severity):
    assert Severity.from_score(severity.baseline_cvss) is severity
