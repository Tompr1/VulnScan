import pytest

from app.risk.severity import Severity
from app.scan_jobs.filtering import FindingFilterPolicy
from app.scan_jobs.processing import FindingProcessor
from app.scan_jobs.validation import FindingValidation, ValidationState
from tests.fakes import StubCvssEnricher, finding, no_compliance

TARGET = "10.0.0.5"


def processor(**overrides) -> FindingProcessor:
    values = {"filter_policy": FindingFilterPolicy(), "compliance_mapper": no_compliance}
    values.update(overrides)
    return FindingProcessor(**values)


def process_one(raw, **overrides):
    report = processor(**overrides).process([raw], TARGET, suppressed=set())
    return report.saved[0] if report.saved else None


def test_un_constat_masque_par_l_utilisateur_n_est_ni_enregistre_ni_compte_comme_rejete():
    report = processor().process([finding("Muted", fingerprint="fp-muted")], TARGET, suppressed={"fp-muted"})

    assert (report.saved, report.dropped, report.total) == ([], 0, 1)


def test_sans_cvss_le_score_est_deduit_de_la_severite_du_plugin():
    saved = process_one(finding("Debug console", severity="high"))

    assert (saved.cvss, saved.risk_score, saved.severity, saved.sla_days) == (8.0, 8.0, Severity.HIGH, 7)


def test_une_cve_listee_kev_devient_critique():
    saved = process_one(finding("Exploited", severity="high", cvss=7.0, is_kev=True))

    assert saved.risk_score == 9.1
    assert saved.severity is Severity.CRITICAL


def test_une_correlation_de_version_provisoire_est_plafonnee_en_confiance():
    raw = finding("Old OpenSSH", cvss=9.8, cve="CVE-2024-6387", evidence="validation_state=provisional validation_method=banner")

    saved = process_one(raw)

    assert saved.confidence == 0.35
    assert saved.severity is Severity.LOW
    assert saved.remediation.startswith("[VALIDATION] This is a provisional version correlation")
    assert "Method: banner." in saved.remediation


def test_un_constat_probablement_corrige_est_rejete_par_defaut():
    report = processor().process([finding("Backported", evidence="validation_state=likely_patched")], TARGET, set())

    assert (len(report.saved), report.dropped) == (0, 1)


def test_un_paquet_local_non_expose_au_reseau_est_rejete():
    raw = finding("Local pkg", cvss=7.5, evidence="network_facing=no validation_method=package_version_match_local_only")

    assert process_one(raw) is None


def test_un_constat_trop_incertain_est_rejete():
    assert process_one(finding("Guess", severity="medium", confidence=0.1)) is None


def test_un_constat_informatif_est_conserve_quelle_que_soit_sa_confiance():
    assert process_one(finding("Banner", severity="info", confidence=0.05)) is not None


def test_le_seuil_de_confiance_est_reglable_par_profil():
    policy = FindingFilterPolicy.from_profile_options({"filtering": {"min_confidence": 0.05}})

    assert process_one(finding("Guess", severity="medium", confidence=0.1), filter_policy=policy) is not None


def test_une_detection_faible_est_ecartee_quand_la_meme_cve_est_validee():
    # Arrange
    validated = finding("Confirmed", fingerprint="fp-1", cve="CVE-2021-41773", cvss=7.5, evidence="validation_state=validated")
    provisional = finding("Version match", fingerprint="fp-2", cve="CVE-2021-41773", cvss=7.5, evidence="validation_state=provisional")

    # Act
    report = processor().process([provisional, validated], TARGET, set())

    # Assert
    assert [f.title for f in report.saved] == ["Confirmed"]
    assert report.dropped == 0


def test_le_cvss_enrichi_remplace_celui_du_plugin_et_renforce_la_confiance():
    enricher = StubCvssEnricher({"CVE-2023-1": (9.8, 1.0)})

    saved = process_one(finding("Vuln", cve="CVE-2023-1", cvss=5.0, confidence=0.6), cvss_enricher=enricher)

    assert (saved.cvss, saved.confidence) == (9.8, 1.0)


def test_sans_donnees_d_enrichissement_la_confiance_d_une_cve_monte_a_0_9():
    # Behaviour kept from the original worker: the enricher answers
    # (current cvss, 0.9) when it knows nothing about the CVE.
    saved = process_one(finding("Vuln", cve="CVE-2023-2", cvss=6.0, confidence=0.5), cvss_enricher=StubCvssEnricher())

    assert saved.confidence == 0.9


def test_l_enrichissement_ne_leve_pas_le_plafond_de_confiance_de_l_etat_de_validation():
    enricher = StubCvssEnricher({"CVE-2023-3": (9.0, 1.0)})
    raw = finding("Probe", cve="CVE-2023-3", evidence="validation_state=probe_negative")

    assert process_one(raw, cvss_enricher=enricher).confidence == 0.20


def test_un_cvss_hors_bornes_est_ignore_au_profit_de_la_severite():
    saved = process_one(finding("Weird", severity="medium", cvss=42.0))

    assert saved.cvss == 5.5


def test_la_politique_sla_est_ajoutee_apres_la_remediation_du_plugin():
    saved = process_one(finding("Header", severity="medium", remediation="Add the header."))

    assert saved.remediation == (
        "Add the header.\n\n[SLA POLICY] This is a MEDIUM severity vulnerability with a 30-day "
        "remediation SLA. Plan patching during the next maintenance window. Review if compensating "
        "controls are already in place."
    )


def test_un_constat_informatif_n_a_pas_de_politique_sla():
    saved = process_one(finding("Banner", severity="info", remediation="Nothing to do."))

    assert saved.remediation == "Nothing to do."


def test_le_referentiel_de_conformite_est_interroge_avec_la_cve_et_le_plugin():
    calls = []

    def mapper(cve, plugin_id):
        calls.append((cve, plugin_id))
        return ["NIST-SI-2"]

    saved = process_one(finding("Vuln", plugin_id="cve.nvd", cve="CVE-2020-1", cvss=5.0), compliance_mapper=mapper)

    assert calls == [("CVE-2020-1", "cve.nvd")]
    assert saved.compliance == ["NIST-SI-2"]


def test_le_rapport_compte_les_constats_par_severite():
    raws = [finding("a", severity="high"), finding("b", severity="high"), finding("c", severity="low")]

    counts = processor().process(raws, TARGET, set()).severity_counts()

    assert counts == {Severity.CRITICAL: 0, Severity.HIGH: 2, Severity.MEDIUM: 0, Severity.LOW: 1, Severity.INFO: 0}


@pytest.mark.parametrize(
    ("evidence", "state", "method"),
    [
        ('validation_state=Validated validation_method="active probe"', ValidationState.VALIDATED, "active probe"),
        ("validation_state=unheard_of", None, ""),
        ("", None, ""),
    ],
)
def test_l_etat_de_validation_est_lu_dans_la_preuve(evidence, state, method):
    validation = FindingValidation.from_evidence(evidence)

    assert (validation.state, validation.method) == (state, method)


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, FindingFilterPolicy()),
        ({"filtering": "oops"}, FindingFilterPolicy()),
        ({"filtering": {"min_confidence": "high"}}, FindingFilterPolicy()),
        ({"filtering": {"min_confidence": 7}}, FindingFilterPolicy(min_confidence=1.0)),
        ({"filtering": {"drop_states": ["PROVISIONAL"], "drop_local_only": False}},
         FindingFilterPolicy(drop_states=frozenset({"provisional"}), drop_local_only=False)),
        ({"filtering": {"drop_states": "provisional"}}, FindingFilterPolicy()),
    ],
)
def test_les_options_de_filtrage_invalides_gardent_leur_valeur_par_defaut(options, expected):
    assert FindingFilterPolicy.from_profile_options(options) == expected


def test_les_cve_d_un_constat_sont_relevees_pour_le_threat_intel():
    raw = finding(
        "Apache 2.4.49 (cve-2021-41773)", cve="CVE-2021-42013", cves=["CVE-2021-40438"],
        description="Also fixes CVE-2021-41524.", references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44790"],
    )

    saved = process_one(raw)

    assert saved.cve_ids == ("CVE-2021-40438", "CVE-2021-41524", "CVE-2021-41773", "CVE-2021-42013", "CVE-2021-44790")
