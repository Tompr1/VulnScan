import pytest

from app.risk.risk_engine import RiskFactors, compute_risk, parse_criticality
from app.risk.severity import Severity


def test_sans_facteur_aggravant_le_risque_vaut_le_score_cvss():
    assert compute_risk(RiskFactors(cvss=6.5)) == 6.5


def test_une_cve_exploitee_kev_augmente_le_risque_de_30_pourcent():
    assert compute_risk(RiskFactors(cvss=7.0, kev=True)) == 9.1


def test_un_exploit_public_connu_augmente_le_risque_de_15_pourcent():
    assert compute_risk(RiskFactors(cvss=6.0, exploit_known=True)) == 6.9


def test_le_risque_ne_depasse_jamais_10():
    assert compute_risk(RiskFactors(cvss=9.5, kev=True, criticality=5)) == 10.0


@pytest.mark.parametrize(("criticality", "expected"), [(1, 4.0), (2, 5.0), (3, 5.5), (4, 6.0), (5, 6.5)])
def test_la_criticite_de_l_actif_module_le_risque(criticality, expected):
    assert compute_risk(RiskFactors(cvss=5.0, criticality=criticality)) == expected


def test_une_confiance_faible_reduit_le_risque_proportionnellement():
    assert compute_risk(RiskFactors(cvss=9.8, confidence=0.5)) == 4.9


def test_une_confiance_nulle_conserve_un_dixieme_du_risque():
    assert compute_risk(RiskFactors(cvss=8.0, confidence=0.0)) == 0.8


def test_une_cve_critique_vue_avec_une_confiance_elevee_reste_critique():
    # 9.8 x 0.9 = 8.82 serait "high" : le plancher de bande la garde "critical".
    risk = compute_risk(RiskFactors(cvss=9.8, confidence=0.9))

    assert risk == 9.0
    assert Severity.from_score(risk) is Severity.CRITICAL


def test_sans_cvss_le_risque_part_de_la_severite_du_plugin():
    assert compute_risk(RiskFactors(cvss=None, plugin_severity=Severity.HIGH)) == 8.0


def test_sans_cvss_ni_severite_le_risque_est_moyen():
    assert compute_risk(RiskFactors(cvss=None)) == 5.0


@pytest.mark.parametrize(
    "invalid",
    [
        {"cvss": 10.5},
        {"cvss": -1.0},
        {"cvss": 5.0, "criticality": 0},
        {"cvss": 5.0, "criticality": 6},
        {"cvss": 5.0, "confidence": 1.2},
    ],
)
def test_des_facteurs_de_risque_hors_bornes_sont_refuses(invalid):
    with pytest.raises(ValueError):
        RiskFactors(**invalid)


@pytest.mark.parametrize(("raw", "expected"), [(3, 3), ("4", 4), (None, 2), ("élevée", 2), (0, 1), (9, 5)])
def test_la_criticite_saisie_par_l_utilisateur_est_ramenee_entre_1_et_5(raw, expected):
    assert parse_criticality(raw) == expected
