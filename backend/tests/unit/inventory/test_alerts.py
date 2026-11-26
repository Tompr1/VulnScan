"""
Inventory alerts: threshold, "new detections only", baseline, deep links,
and the alerter wiring (fake history, spy sender).
"""
from dataclasses import dataclass

import pytest

from app.inventory.alerts import (
    AlertItem,
    AlertPolicy,
    AlertSettings,
    DeviceLinks,
    InventoryAlert,
    InventoryAlerter,
    KnownIssue,
)
from app.risk.severity import Severity
from tests.fakes import SpyNotifier


def issue(fingerprint="fp-1", rule="os_vulnerable", severity="high", is_kev=False, device_id=7, title=None) -> KnownIssue:
    return KnownIssue(fingerprint, f"inventory.{rule}", severity, is_kev, device_id, title or f"{rule} — PC-0{device_id}")


# ── Settings ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ({}, AlertSettings(Severity.HIGH, True)),
        ({"min_severity": "critical", "always_kev": False}, AlertSettings(Severity.CRITICAL, False)),
        ({"min_severity": "MEDIUM"}, AlertSettings(Severity.MEDIUM, True)),
        ({"min_severity": "urgent", "always_kev": "yes"}, AlertSettings(Severity.HIGH, True)),  # invalid: defaults
        ({"always_kev": 0}, AlertSettings(Severity.HIGH, True)),  # not a boolean: default, not False
    ],
)
def test_les_reglages_d_alerte_stockes_sont_relus_avec_des_valeurs_par_defaut_sures(stored, expected):
    assert AlertSettings.from_stored(stored) == expected


def test_les_reglages_d_alerte_se_stockent_et_se_relisent_a_l_identique():
    settings = AlertSettings(Severity.MEDIUM, False)

    assert AlertSettings.from_stored(settings.to_stored()) == settings


@pytest.mark.parametrize(
    ("severity", "is_kev", "passes"),
    [("critical", False, True), ("high", False, True), ("medium", False, False), ("low", True, True), ("bizarre", False, False)],
)
def test_le_seuil_par_defaut_retient_critique_haute_et_toute_cve_exploitee(severity, is_kev, passes):
    assert AlertSettings().passes(issue(severity=severity, is_kev=is_kev)) is passes


def test_sans_always_kev_une_cve_exploitee_suit_le_seuil_de_gravite():
    assert not AlertSettings(Severity.HIGH, always_kev=False).passes(issue(severity="low", is_kev=True))


# ── Events ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("rule", "is_kev", "events"),
    [
        ("app_vulnerable", True, ["device_vulnerability", "cisa_kev_match"]),
        ("os_vulnerable", False, ["device_vulnerability"]),
        ("os_unsupported", False, ["device_os_issue"]),
        ("android_patch_outdated", False, ["device_os_issue"]),
        ("app_outdated", False, ["device_software_issue"]),
        ("audit_incomplete", False, []),
    ],
)
def test_chaque_regle_correspond_a_un_evenement_de_notification(rule, is_kev, events):
    assert issue(rule=rule, is_kev=is_kev).events == events


@dataclass
class Row:
    fingerprint: str = "fp-1"
    plugin_id: str = "inventory.os_vulnerable"
    severity: object = Severity.CRITICAL
    is_kev: bool = True
    device_id: int = 7
    title: str = "Windows — PC-07"


def test_un_constat_enregistre_devient_un_probleme_connu():
    assert KnownIssue.of(Row()) == KnownIssue("fp-1", "inventory.os_vulnerable", "critical", True, 7, "Windows — PC-07")
    assert KnownIssue.of(Row(severity="high")).severity == "high"


# ── Policy ────────────────────────────────────────────────────────────────────

def select(current, previous, settings=AlertSettings()):
    return AlertPolicy(settings).select(current, previous)


def test_au_premier_audit_tout_ce_qui_passe_le_seuil_forme_le_bilan_initial():
    current = [issue("a", severity="high"), issue("b", severity="low"), issue("c", severity="critical", device_id=8)]

    selected, baseline, resolved = select(current, None)

    assert ([i.fingerprint for i in selected], baseline, resolved) == (["c", "a"], True, 0)


def test_seuls_les_nouveaux_problemes_sont_alertes_ensuite():
    previous = [issue("a"), issue("gone")]
    current = [issue("a"), issue("new")]

    selected, baseline, resolved = select(current, previous)

    assert ([i.fingerprint for i in selected], baseline, resolved) == (["new"], False, 1)


def test_un_probleme_qui_s_aggrave_jusqu_au_seuil_devient_une_nouvelle_alerte():
    selected, _, _ = select([issue("a", severity="critical")], [issue("a", severity="medium")])

    assert [i.fingerprint for i in selected] == ["a"]


def test_un_probleme_qui_reste_au_dessus_du_seuil_n_est_pas_repete():
    assert select([issue("a", severity="critical")], [issue("a", severity="high")])[0] == []


def test_les_problemes_sans_appareil_ne_sont_jamais_alertes():
    notice = issue("incomplete", rule="audit_incomplete", severity="critical", device_id=None)

    assert select([notice], [])[0] == []
    assert select([], [notice])[2] == 0  # nor counted as resolved


def test_les_cve_exploitees_passent_en_tete_puis_par_gravite():
    current = [issue("low-kev", severity="low", is_kev=True), issue("crit", severity="critical"), issue("high", severity="high")]

    assert [i.fingerprint for i in select(current, [])[0]] == ["low-kev", "crit", "high"]


# ── Alert ─────────────────────────────────────────────────────────────────────

def item(fingerprint="a", device_id=7, name="PC-07", **options) -> AlertItem:
    return AlertItem(issue(fingerprint, device_id=device_id, title=f"Chrome 131 has 2 known vulnerabilities — {name}", **options), name)


def test_le_titre_d_une_alerte_retire_le_nom_de_l_appareil():
    assert item().headline == "Chrome 131 has 2 known vulnerabilities"
    assert AlertItem(issue(title="Sans suffixe"), "PC-07").headline == "Sans suffixe"


def test_l_objet_resume_les_nouveaux_problemes_et_les_cve_exploitees():
    alert = InventoryAlert(12, "intune:Tenant", (item("a"), item("b", is_kev=True), item("c", device_id=8)), resolved=1, open_issues=40)

    assert alert.subject == "v0cday: 3 new device issues on 2 devices (1 actively exploited)"
    assert alert.footer == "Audit job #12 of intune:Tenant: 1 issue resolved since the previous audit, 40 open in total."


def test_l_objet_du_bilan_initial_le_dit():
    alert = InventoryAlert(12, "intune:Tenant", (item("a"),), baseline=True)

    assert alert.subject == "v0cday: first device audit of intune:Tenant, 1 open issue on 1 device"
    assert "only new detections are alerted" in alert.footer


@pytest.mark.parametrize(
    ("base", "device", "devices"),
    [
        ("https://v0cday.example.com/", "https://v0cday.example.com/#/c/3/inventory/devices/7", "https://v0cday.example.com/#/c/3/inventory"),
        ("", None, None),
        (None, None, None),
    ],
)
def test_les_liens_menent_a_la_fiche_de_l_appareil_chez_son_client(base, device, devices):
    links = DeviceLinks(base)

    assert (links.device(3, 7), links.devices(3)) == (device, devices)


# ── Alerter ───────────────────────────────────────────────────────────────────

@dataclass
class Job:
    id: int = 12
    workspace_id: int = 1
    target: str = "intune:Tenant"


class FakeHistory:
    def __init__(self, previous=None, settings=AlertSettings()):
        self.previous = previous
        self.settings = settings
        self.asked_names = None

    def previous_issues(self, job_id):
        return self.previous

    def device_names(self, device_ids):
        self.asked_names = set(device_ids)
        return {7: "PC-COMPTA-04"}

    def alert_settings(self, workspace_id):
        return self.settings


def row(fingerprint, severity="high", device_id=7, is_kev=False):
    return Row(fingerprint, "inventory.app_vulnerable", severity, is_kev, device_id, f"Chrome — PC-0{device_id}")


def test_l_alerteur_envoie_une_seule_alerte_avec_les_nouveaux_problemes_et_leurs_liens_chez_le_client():
    history, sender = FakeHistory(previous=[issue("old", device_id=7)]), SpyNotifier()
    alerter = InventoryAlerter(history, sender, DeviceLinks("https://v0cday.example.com"))

    alert = alerter.announce(Job(workspace_id=4), [row("old"), row("new", device_id=7), row("new-2", device_id=9), row("quiet", severity="low")])

    [(workspace, sent)] = sender.alerts
    assert workspace == 4 and sent is alert
    assert [(i.issue.fingerprint, i.device_name, i.link) for i in sent.items] == [
        ("new", "PC-COMPTA-04", "https://v0cday.example.com/#/c/4/inventory/devices/7"),
        ("new-2", "device #9", "https://v0cday.example.com/#/c/4/inventory/devices/9"),  # name unknown: still alerted
    ]
    assert (sent.baseline, sent.resolved, sent.open_issues, sent.devices_url) == (False, 0, 4, "https://v0cday.example.com/#/c/4/inventory")
    assert history.asked_names == {7, 9}


def test_sans_nouveau_probleme_rien_n_est_envoye():
    sender = SpyNotifier()

    assert InventoryAlerter(FakeHistory(previous=[issue("old")]), sender).announce(Job(), [row("old")]) is None
    assert sender.alerts == []


def test_le_premier_audit_envoie_le_bilan_initial():
    sender = SpyNotifier()

    InventoryAlerter(FakeHistory(previous=None), sender).announce(Job(), [row("a"), row("b")])

    [(_, alert)] = sender.alerts
    assert alert.baseline and len(alert.items) == 2


def test_le_seuil_du_workspace_est_applique():
    sender = SpyNotifier()
    history = FakeHistory(previous=[], settings=AlertSettings(Severity.CRITICAL, always_kev=False))

    InventoryAlerter(history, sender).announce(Job(), [row("high"), row("crit", severity="critical")])

    assert [i.issue.fingerprint for i in sender.alerts[0][1].items] == ["crit"]
