"""Le message « sonde hors ligne / de retour », sur chaque canal."""
from datetime import datetime, timedelta, timezone

import pytest

from app.core.workspace_settings import DEFAULT_NOTIFICATION_PREFS
from app.probes.alerts import ProbeStatusAlert, duration_text
from app.scan_jobs.notifications import EmailChannel, Integration, ScanNotifier, SlackChannel, TeamsChannel, WebhookChannel
from tests.fakes import SpyChannel, StubIntegrationSource

AT = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)


def alerte(online=False, **overrides):
    values = {"probe_id": 7, "probe_name": "Paris", "client_name": "Acme", "online": online,
              "since": AT - timedelta(minutes=95), "at": AT, "waiting_jobs": 2,
              "url": "https://soc.example/#/root/probes"}
    values.update(overrides)
    return ProbeStatusAlert(**values)


def envoyes(channel_class):
    sent = []
    channel_class(lambda *args: sent.append(args)).probe_status({"url": "x"}, alerte())
    return sent


@pytest.mark.parametrize(("secondes", "texte"), [(20, "1 min"), (600, "10 min"), (95 * 60, "1 h 35"), (3 * 86400, "3 days")])
def test_les_durees_se_lisent_d_un_coup_d_oeil(secondes, texte):
    assert duration_text(secondes) == texte


def test_le_message_dit_ce_qui_se_passe_et_combien_de_scans_attendent():
    assert alerte().subject == "v0cday: scan probe Paris (Acme) is OFFLINE"
    assert alerte().lines[0] == "No contact for 1 h 35: scans routed to this probe wait, then fail."
    assert alerte().lines[-1] == "2 scan(s) waiting for it."
    assert alerte(online=True).lines[0] == "The probe is connected again after 1 h 35 offline."


def test_slack_recoit_un_titre_et_un_bouton_vers_les_sondes():
    [(config, message)] = envoyes(SlackChannel)

    assert message["text"] == alerte().subject
    assert message["blocks"][-1]["elements"][0]["url"] == "https://soc.example/#/root/probes"


def test_le_webhook_recoit_un_evenement_par_etat():
    sent = []
    channel = WebhookChannel(lambda *args: sent.append(args))
    channel.probe_status({}, alerte())
    channel.probe_status({}, alerte(online=True))

    assert [payload["event"] for _, payload in sent] == ["probe_offline", "probe_online"]
    assert sent[0][1]["data"]["waiting_jobs"] == 2


def test_l_email_et_teams_portent_le_sujet_et_le_lien():
    [(_, subject, body)] = envoyes(EmailChannel)
    [(_, teams)] = envoyes(TeamsChannel)

    assert subject == alerte().subject and body.endswith("Scan probes: https://soc.example/#/root/probes")
    assert teams["title"] == alerte().subject


def test_l_alerte_suit_les_preferences_du_client():
    slack, email = SpyChannel(), SpyChannel()
    prefs = {"probe_status": {"slack": True, "email": False, "webhook": False}}
    source = StubIntegrationSource([Integration("slack", {"u": 1}), Integration("email", {"to": "x"})], prefs)

    ScanNotifier(source, {"slack": slack, "email": email}).probe_status(1, alerte())

    assert len(slack.alerts) == 1 and email.alerts == []


def test_par_defaut_les_clients_sont_prevenus_sur_tous_les_canaux():
    assert DEFAULT_NOTIFICATION_PREFS["probe_status"] == {"email": True, "slack": True, "webhook": True}
