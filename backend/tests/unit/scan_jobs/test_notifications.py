from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.inventory.alerts import AlertItem, InventoryAlert, KnownIssue
from app.risk.severity import Severity
from app.scan_jobs.notifications import (
    EmailChannel,
    Integration,
    ScanFailure,
    ScanNotifier,
    ScanSummary,
    SlackChannel,
    TeamsChannel,
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


# ── Device alerts (inventory audits) ──────────────────────────────────────────

DEVICE_EVENTS_ON = {
    "device_vulnerability": {"slack": True, "email": True, "webhook": True},
    "device_software_issue": {"slack": True, "email": False, "webhook": True},
}


def alert_item(n=1, rule="app_vulnerable", severity="critical", is_kev=False, name="PC-COMPTA-04",
               link="https://vs.example/#/inventory/devices/7") -> AlertItem:
    title = f"Google Chrome 131 has {n} known vulnerabilities — {name}"
    return AlertItem(KnownIssue(f"fp-{n}-{rule}", f"inventory.{rule}", severity, is_kev, 7, title), name, link)


def device_alert(*items, **overrides) -> InventoryAlert:
    values = {"job_id": 12, "target": "intune:Tenant", "items": items or (alert_item(),), "resolved": 2,
              "open_issues": 30, "devices_url": "https://vs.example/#/inventory"}
    values.update(overrides)
    return InventoryAlert(**values)


def captured(channel_class):
    sent = []
    return channel_class(lambda *args: sent.append(args)), sent


def test_slack_liste_chaque_appareil_avec_son_lien_et_un_bouton_vers_l_inventaire():
    channel, sent = captured(SlackChannel)

    channel.device_alert({}, device_alert(alert_item(is_kev=True)))

    [(_, message)] = sent
    assert message["text"] == "VulnScan: 1 new device issue on 1 device (1 actively exploited)"
    blocks = message["blocks"]
    assert blocks[0]["text"]["text"] == "1 new device issue on 1 device (1 actively exploited)"
    assert blocks[1]["text"]["text"] == (
        "• *[CRITICAL · KEV]* <https://vs.example/#/inventory/devices/7|PC-COMPTA-04> — Google Chrome 131 has 1 known vulnerabilities"
    )
    assert blocks[-1]["elements"][0]["url"] == "https://vs.example/#/inventory"


def test_slack_echappe_les_caracteres_de_controle_des_noms():
    channel, sent = captured(SlackChannel)

    channel.device_alert({}, device_alert(alert_item(name="<PC & co>", link=None), devices_url=None))

    line = sent[0][1]["blocks"][1]["text"]["text"]
    assert "*&lt;PC &amp; co&gt;*" in line
    assert all(block["type"] != "actions" for block in sent[0][1]["blocks"])  # no URL, no button


def test_slack_limite_le_nombre_de_lignes_et_la_taille_des_sections():
    channel, sent = captured(SlackChannel)

    channel.device_alert({}, device_alert(*(alert_item(n) for n in range(1, 31))))

    sections = [b["text"]["text"] for b in sent[0][1]["blocks"] if b["type"] == "section"]
    lines = "\n".join(sections).splitlines()
    assert len(lines) == 21 and lines[-1] == "… and 10 more"
    assert all(len(text) <= 2900 for text in sections)


def test_teams_recoit_une_carte_avec_des_liens_markdown():
    channel, sent = captured(TeamsChannel)

    channel.device_alert({}, device_alert())

    card = sent[0][1]["attachments"][0]["content"]
    assert card["body"][1]["text"] == (
        "**[CRITICAL]** [PC-COMPTA-04](https://vs.example/#/inventory/devices/7) — Google Chrome 131 has 1 known vulnerabilities"
    )
    assert card["actions"][0]["url"] == "https://vs.example/#/inventory"


def test_le_webhook_recoit_tous_les_problemes_sans_limite():
    channel, sent = captured(WebhookChannel)

    channel.device_alert({}, device_alert(*(alert_item(n) for n in range(1, 31))))

    payload = sent[0][1]
    assert payload["event"] == "inventory_alert"
    assert len(payload["data"]["issues"]) == 30
    assert payload["data"]["issues"][0] == {
        "device_id": 7, "device": "PC-COMPTA-04", "rule": "app_vulnerable",
        "title": "Google Chrome 131 has 1 known vulnerabilities", "severity": "critical", "is_kev": False,
        "fingerprint": "fp-1-app_vulnerable", "url": "https://vs.example/#/inventory/devices/7",
    }
    assert (payload["data"]["resolved"], payload["data"]["open_issues"], payload["data"]["baseline"]) == (2, 30, False)


def test_l_e_mail_donne_le_lien_de_chaque_appareil():
    channel, sent = captured(EmailChannel)

    channel.device_alert({}, device_alert())

    [(_, subject, body)] = sent
    assert subject == "VulnScan: 1 new device issue on 1 device"
    assert body.splitlines()[:2] == [
        "- [CRITICAL] PC-COMPTA-04: Google Chrome 131 has 1 known vulnerabilities",
        "  https://vs.example/#/inventory/devices/7",
    ]
    assert body.endswith("Device inventory: https://vs.example/#/inventory")


def test_chaque_integration_ne_recoit_que_les_problemes_de_ses_evenements():
    slack, email = SpyChannel(), SpyChannel()
    source = StubIntegrationSource([Integration("slack", {}), Integration("email", {})], DEVICE_EVENTS_ON)
    notifier = ScanNotifier(source, {"slack": slack, "email": email}, should_notify)
    vulnerability, outdated = alert_item(1), alert_item(2, rule="app_outdated", severity="high")

    notifier.device_alert(1, device_alert(vulnerability, outdated))

    assert [i.issue.rule for i in slack.alerts[0][1].items] == ["app_vulnerable", "app_outdated"]
    assert [i.issue.rule for i in email.alerts[0][1].items] == ["app_vulnerable"]


def test_une_integration_sans_evenement_concerne_ne_recoit_rien():
    email = SpyChannel()
    source = StubIntegrationSource([Integration("email", {})], DEVICE_EVENTS_ON)

    ScanNotifier(source, {"email": email}, should_notify).device_alert(1, device_alert(alert_item(rule="app_outdated")))

    assert email.alerts == []


def test_une_cve_exploitee_passe_par_l_evenement_kev_meme_si_les_vulnerabilites_sont_coupees():
    email = SpyChannel()
    prefs = {"device_vulnerability": {"email": False}, "cisa_kev_match": {"email": True}}
    notifier = ScanNotifier(StubIntegrationSource([Integration("email", {})], prefs), {"email": email}, should_notify)

    notifier.device_alert(1, device_alert(alert_item(1, is_kev=True), alert_item(2)))

    assert [i.issue.is_kev for i in email.alerts[0][1].items] == [True]


def test_une_integration_en_panne_n_empeche_pas_les_autres_alertes():
    broken, email = SpyChannel(error=RuntimeError("SMTP down")), SpyChannel()
    source = StubIntegrationSource([Integration("slack", {}), Integration("email", {})], DEVICE_EVENTS_ON)

    ScanNotifier(source, {"slack": broken, "email": email}, should_notify).device_alert(1, device_alert())

    assert len(email.alerts) == 1


def test_des_integrations_illisibles_n_empechent_pas_la_fin_du_job():
    source = StubIntegrationSource(error=RuntimeError("db down"))

    ScanNotifier(source, {}, should_notify).device_alert(1, device_alert())  # no exception


def test_slack_repartit_les_lignes_longues_sur_plusieurs_sections():
    channel, sent = captured(SlackChannel)
    long_items = [
        AlertItem(KnownIssue(f"fp-{n}", "inventory.app_vulnerable", "high", False, n, "x" * 400 + f" — PC-{n}"), f"PC-{n}")
        for n in range(20)
    ]

    channel.device_alert({}, device_alert(*long_items))

    sections = [b["text"]["text"] for b in sent[0][1]["blocks"] if b["type"] == "section"]
    assert len(sections) > 1
    assert all(len(text) <= 2900 for text in sections)
    assert sum(len(text.splitlines()) for text in sections) == 20
