import pytest

from app.risk.cvss_engine import cvss_baseline_from_severity, cvss_v3_vector_to_score, severity_from_score
from app.risk.severity import Severity
from app.risk.sla_engine import assign_sla_days, sla_policy_text


def test_le_libelle_de_severite_est_renvoye_sous_forme_de_texte():
    assert severity_from_score(7.5) == "high"


def test_le_score_de_reference_d_un_libelle_inconnu_est_absent():
    assert cvss_baseline_from_severity("bogus") is None


def test_le_score_de_reference_moyen_est_5_5():
    assert cvss_baseline_from_severity("MEDIUM") == 5.5


def test_un_vecteur_cvss_critique_donne_9_8():
    assert cvss_v3_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_un_vecteur_sans_impact_donne_0():
    assert cvss_v3_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


@pytest.mark.parametrize("vector", ["AV:N:X/AC:L", None, 42])
def test_un_vecteur_illisible_ne_donne_aucun_score(vector):
    assert cvss_v3_vector_to_score(vector) is None


@pytest.mark.parametrize(
    ("severity", "days"),
    [(Severity.CRITICAL, 2), ("high", 7), ("MEDIUM", 30), ("low", 90), ("info", 365), ("unknown", 365)],
)
def test_le_delai_de_remediation_depend_de_la_severite(severity, days):
    assert assign_sla_days(severity) == days


def test_une_vulnerabilite_haute_rappelle_son_delai_de_7_jours():
    text = sla_policy_text(Severity.HIGH)

    assert text.startswith("[SLA POLICY] This is a HIGH severity vulnerability with a 7-day remediation SLA.")


def test_un_constat_informatif_n_a_pas_de_politique_sla():
    assert sla_policy_text(Severity.INFO) is None
