from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.risk.severity import Severity
from app.scan_jobs.notifications import (
    Integration,
    ScanFailure,
    ScanNotifier,
    ScanSummary,
    SlackChannel,
    WebhookChannel,
    build_summary,
)
from app.scanner.notifier import should_notify
from tests.fakes import SpyChannel, StubIntegrationSource

ALL_ON = {event: {"slack": True, "email": True, "webhook": True} for event in ("scan_completed", "scan_failed", "critical_finding")}


def summary(**overrides) -> ScanSummary:
    values = {
        "job_id": 12,
        "target": "10.0.0.5",
        "scan_type": "internal",
        "saved_count": 3,
        "severity_counts": {Severity.HIGH: 2, Severity.LOW: 1},
        "duration_seconds": 125,
    }
    values.update(overrides)
    return ScanSummary(**values)


def test_le_niveau_de_risque_est_celui_de_la_pire_severite_trouvee():
    assert summary().risk_level == "HIGH"
    assert summary(severity_counts={}).risk_level == "INFO"


def test_la_duree_est_affichee_en_minutes_et_secondes():
    assert summary().duration_text == "2m 5s"
    assert summary(duration_seconds=42).duration_text == "42s"


def test_un_constat_critique_et_une_cve_kev_declenchent_leurs_evenements():
    events = summary(severity_counts={Severity.CRITICAL: 1}, has_kev=True).triggered_events

    assert events == ["scan_completed", "critical_finding", "cisa_kev_match"]


def test_chaque_integration_active_recoit_la_fin_de_scan():
    # Arrange
    slack, email = SpyChannel(), SpyChannel()
    source = StubIntegrationSource([Integration("slack", {"url": "s"}), Integration("email", {"to": "e"})], ALL_ON)
    notifier = ScanNotifier(source, {"slack": slack, "email": email}, should_notify)

    # Act
    notifier.scan_completed(1, summary())

    # Assert
    assert [cfg for cfg, _ in slack.completed] == [{"url": "s"}]
    assert [cfg for cfg, _ in email.completed] == [{"to": "e"}]


def test_une_integration_est_ignoree_si_ses_preferences_ne_couvrent_pas_l_evenement():
    slack = SpyChannel()
    prefs = {"scan_completed": {"slack": False}}
    notifier = ScanNotifier(StubIntegrationSource([Integration("slack", {})], prefs), {"slack": slack}, should_notify)

    notifier.scan_completed(1, summary())

    assert slack.completed == []


def test_un_fournisseur_sans_canal_est_ignore_sans_erreur():
    notifier = ScanNotifier(StubIntegrationSource([Integration("pager", {})], ALL_ON), {}, should_notify)

    notifier.scan_failed(1, ScanFailure(1, "t", "boom", "scan_engine"))


def test_une_integration_en_panne_n_empeche_pas_les_autres_d_etre_notifiees():
    broken, webhook = SpyChannel(error=RuntimeError("timeout")), SpyChannel()
    source = StubIntegrationSource([Integration("slack", {}), Integration("webhook", {})], ALL_ON)

    ScanNotifier(source, {"slack": broken, "webhook": webhook}, should_notify).scan_failed(1, ScanFailure(1, "t", "boom", "x"))

    assert len(webhook.failed) == 1


def test_une_panne_de_lecture_des_integrations_n_echoue_pas_le_scan():
    source = StubIntegrationSource(error=RuntimeError("db down"))

    ScanNotifier(source, {}, should_notify).scan_completed(1, summary())


def test_le_message_slack_propose_le_tableau_de_bord_quand_il_est_configure():
    sent = []
    SlackChannel(send=lambda cfg, msg: sent.append(msg)).scan_completed({"dashboard_url": "https://vs/d"}, summary())

    assert sent[0]["blocks"][-1]["elements"][0]["url"] == "https://vs/d"
    assert sent[0]["text"] == "Scan complete: 10.0.0.5 | Job #12 | 3 findings | Risk HIGH"


def test_le_webhook_recoit_les_compteurs_de_toutes_les_severites():
    sent = []
    WebhookChannel(send=lambda cfg, payload: sent.append(payload)).scan_completed({}, summary())

    assert sent[0]["event"] == "scan_done"
    assert sent[0]["data"]["severities"] == {"critical": 0, "high": 2, "medium": 0, "low": 1, "info": 0}


@dataclass
class _Saved:
    title: str
    risk_score: float
    severity: Severity = Severity.LOW
    is_kev: bool = False


def test_le_resume_classe_les_constats_par_risque_et_en_garde_dix():
    # Arrange
    findings = [_Saved(f"f{i}", risk_score=float(i)) for i in range(12)] + [_Saved("kev", 0.0, is_kev=True)]
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Act
    result = build_summary(1, "t", "internal", findings, {}, created, created + timedelta(seconds=90))

    # Assert
    assert [f.title for f in result.top_findings][:3] == ["f11", "f10", "f9"]
    assert len(result.top_findings) == 10
    assert result.has_kev, "KEV is detected on every saved finding, not only the top ten"
    assert result.duration_seconds == 90
