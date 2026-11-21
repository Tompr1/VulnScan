"""
Audit rules, fleet baseline and DeviceAuditor — on plain Device objects,
with a canned endoflife.date catalog (no network).
"""
from datetime import date

import pytest

from app.inventory.audit.auditor import DeviceAuditor
from app.inventory.audit.fleet import FleetBaseline, app_family, newest_apps, os_line
from app.inventory.audit.rules import (
    AndroidPatchLevelRule,
    AppSupportRule,
    AppUpdateRule,
    AuditContext,
    AuditPolicy,
    LifecycleLookup,
    OsSupportRule,
    OsUpdateRule,
    default_rules,
)
from app.inventory.domain import Device, InstalledApp, Platform
from tests.unit.inventory.eol_fixtures import StaticSupportCatalog

TODAY = date(2026, 11, 21)
_ids = iter(range(1, 10_000))


def windows(build: str = "10.0.26200.7171", *apps: InstalledApp, name: str | None = None) -> Device:
    number = next(_ids)
    return Device(f"id-{number}", name or f"PC-{number:02d}", Platform.WINDOWS, os_name="Windows", os_version=build, apps=apps)


def mobile(platform: Platform, os_name: str, os_version: str, patch: str | None = None) -> Device:
    number = next(_ids)
    return Device(f"id-{number}", f"TEL-{number:02d}", platform, os_name=os_name, os_version=os_version, security_patch_level=patch)


def context(*fleet: Device, catalog=None, policy: AuditPolicy | None = None) -> AuditContext:
    policy = policy or AuditPolicy()
    return AuditContext(
        today=TODAY,
        lifecycle=LifecycleLookup(catalog or StaticSupportCatalog()),
        fleet=FleetBaseline.of(fleet, policy.fleet_min_devices),
        policy=policy,
    )


def evaluate(rule, device: Device, *others: Device, **options):
    return rule.evaluate(device, context(device, *others, **options))


# ── Fleet baseline ────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("name", "family"),
    [
        ("7-Zip 24.08 (x64)", "7-zip"),
        ("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33135", "microsoft visual c++ 2015-2022 redistributable"),
        ("Mozilla Firefox (x64 fr)", "mozilla firefox"),
        ("Python 3.12.4 (64-bit)", "python"),
        ("Adobe Acrobat Reader DC - Français", "adobe acrobat reader dc - français"),
        ("Zoom Workplace v6.2.11", "zoom workplace"),
    ],
)
def test_la_famille_d_une_application_ignore_version_architecture_et_langue(name, family):
    assert app_family(name) == family


def test_un_appareil_est_juge_sur_sa_copie_la_plus_recente_d_une_application():
    apps = [InstalledApp("Java 8 (x86)", "8.0.4310"), InstalledApp("Java 8 (x64)", "8.0.4510"), InstalledApp("Outil", "inconnue")]

    assert [app.version for app in newest_apps(apps)] == ["8.0.4510"]


@pytest.mark.parametrize(
    ("platform", "os_version", "line"),
    [
        (Platform.WINDOWS, "10.0.22631.4317", (Platform.WINDOWS, "10.0.22631")),
        (Platform.MACOS, "14.4.1 (23E224)", (Platform.MACOS, "14.4")),
        (Platform.ANDROID, "14", None),  # nothing to compare within a single-part version
        (Platform.WINDOWS, None, None),
    ],
)
def test_la_ligne_de_version_d_un_systeme_retire_la_derniere_partie(platform, os_version, line):
    assert os_line(Device("x", "PC", platform, os_version=os_version)) == line


def test_la_reference_du_parc_est_la_version_la_plus_recente_presente_sur_deux_appareils():
    fleet = FleetBaseline.of([
        windows("10.0.26200.6000", InstalledApp("7-Zip 23.01 (x64)", "23.01")),
        windows("10.0.26200.7171", InstalledApp("7-Zip 24.08 (x64)", "24.08")),
        windows("10.0.26200.7171", InstalledApp("7-Zip 24.08 (x64)", "24.08")),
        windows("10.0.26200.7300", InstalledApp("7-Zip 24.09 (x64)", "24.09")),  # a single early adopter
    ])

    assert fleet.newest_app(InstalledApp("7-Zip 23.01 (x64)", "23.01")).version == "24.08"
    assert fleet.newest_app(InstalledApp("7-Zip 23.01 (x64)", "23.01")).devices == 2
    assert fleet.newest_os(windows("10.0.26200.1")).version == "10.0.26200.7171"


def test_le_parc_compare_un_systeme_a_sa_seule_ligne_de_version():
    fleet = FleetBaseline.of([windows("10.0.26200.7171") for _ in range(3)])

    assert fleet.newest_os(windows("10.0.22631.4317")) is None  # 23H2 is not late on 25H2 updates


def test_le_parc_compare_une_application_d_une_annee_a_l_autre():
    fleet = FleetBaseline.of([windows("10.0.26200.1", InstalledApp("7-Zip 25.01 (x64)", "25.01")) for _ in range(2)])

    assert fleet.newest_app(InstalledApp("7-Zip 24.08 (x64)", "24.08")).version == "25.01"


def test_le_parc_exige_au_moins_un_appareil():
    with pytest.raises(ValueError):
        FleetBaseline.of([], min_devices=0)


# ── OS support ────────────────────────────────────────────────────────────────

def test_un_windows_hors_support_est_signale_en_severite_haute():
    [issue] = evaluate(OsSupportRule(), windows("10.0.22631.4317"))

    assert (issue.rule, issue.severity, issue.subject) == ("os_unsupported", "high", "windows:11-23h2-w")
    assert issue.title == "Windows 11 23H2 (W) is no longer supported"
    assert "2025-11-11" in issue.description
    assert "Enterprise and Education editions are supported longer" in issue.description
    assert ("End of support", "2025-11-11") in issue.evidence
    assert issue.references == ("https://endoflife.date/windows",)


def test_une_fin_de_support_proche_est_annoncee_avant_la_date():
    [issue] = evaluate(OsSupportRule(), mobile(Platform.LINUX, "Ubuntu", "22.04.5"),
                       catalog=StaticSupportCatalog({"ubuntu": [{"cycle": "22.04", "eol": "2026-12-21", "latest": "22.04.5"}]}))

    assert (issue.rule, issue.severity) == ("os_support_ending", "low")
    assert issue.title == "Ubuntu 22.04 support ends in 30 days"


def test_la_fenetre_d_alerte_avant_fin_de_support_est_reglable():
    device = mobile(Platform.LINUX, "Ubuntu", "22.04.5")
    catalog = StaticSupportCatalog({"ubuntu": [{"cycle": "22.04", "eol": "2026-12-21", "latest": "22.04.5"}]})

    assert evaluate(OsSupportRule(), device, catalog=catalog, policy=AuditPolicy(support_warning_days=29)) == []
    assert len(evaluate(OsSupportRule(), device, catalog=catalog, policy=AuditPolicy(support_warning_days=30))) == 1


@pytest.mark.parametrize(
    "device",
    [
        windows("10.0.26200.7171"),  # 25H2: supported until 2027
        mobile(Platform.MACOS, "macOS", "26.7.3"),  # no end announced
        mobile(Platform.LINUX, "Linux", "6.8.0"),  # distribution unknown
        mobile(Platform.OTHER, "ChromeOS", "128.0"),
    ],
)
def test_un_systeme_supporte_ou_non_identifie_ne_produit_rien(device):
    assert evaluate(OsSupportRule(), device) == []


def test_un_android_dont_la_version_n_est_plus_supportee_est_signale():
    [issue] = evaluate(OsSupportRule(), mobile(Platform.ANDROID, "Android", "12"))

    assert (issue.rule, issue.subject) == ("os_unsupported", "android:12")
    assert "Enterprise" not in issue.description  # the edition note is Windows-only


def test_sans_catalogue_le_support_n_est_pas_verifie_et_le_produit_est_note():
    ctx = context(catalog=StaticSupportCatalog(unavailable=("windows",)))

    assert OsSupportRule().evaluate(windows("10.0.22631.4317"), ctx) == []
    assert ctx.lifecycle.unavailable == {"windows"}


# ── OS updates ────────────────────────────────────────────────────────────────

def test_un_ios_en_retard_sur_la_derniere_version_de_l_editeur_est_signale():
    [issue] = evaluate(OsUpdateRule(), mobile(Platform.IOS, "iOS", "18.6"))

    assert (issue.rule, issue.severity, issue.confidence, issue.subject) == ("os_outdated", "medium", 1.0, "ios")
    assert issue.title == "iOS is not up to date (18.6, 18.7.12 available)"
    assert "published by the vendor" in issue.description


def test_windows_est_compare_au_parc_faute_de_mise_a_jour_mensuelle_chez_l_editeur():
    late = windows("10.0.26200.6000")

    [issue] = evaluate(OsUpdateRule(), late, windows("10.0.26200.7171"), windows("10.0.26200.7171"))

    assert (issue.confidence, issue.title) == (0.8, "Windows is not up to date (10.0.26200.6000, 10.0.26200.7171 available)")
    assert "already installed on 2 devices" in issue.description


def test_un_systeme_a_jour_ne_produit_rien():
    current = windows("10.0.26200.7171")

    assert evaluate(OsUpdateRule(), current, windows("10.0.26200.7171")) == []
    assert evaluate(OsUpdateRule(), mobile(Platform.IOS, "iOS", "18.7.12")) == []
    assert evaluate(OsUpdateRule(), mobile(Platform.IOS, "iOS", "18.8")) == []  # newer than the catalog


def test_la_reference_editeur_prime_sur_le_parc_quand_elle_est_precise():
    # The fleet runs a version newer than the vendor's (stale catalog): the vendor decides.
    device = mobile(Platform.IOS, "iOS", "18.7.12")
    ahead = [mobile(Platform.IOS, "iOS", "18.7.13") for _ in range(2)]

    assert evaluate(OsUpdateRule(), device, *ahead) == []


def test_un_systeme_hors_support_n_est_pas_signale_en_plus_comme_non_a_jour():
    assert evaluate(OsUpdateRule(), mobile(Platform.IOS, "iOS", "17.4")) == []


def test_sans_catalogue_windows_reste_compare_au_parc():
    late = windows("10.0.22631.4000")
    fleet = [windows("10.0.22631.4317"), windows("10.0.22631.4317")]

    [issue] = evaluate(OsUpdateRule(), late, *fleet, catalog=StaticSupportCatalog(unavailable=("windows",)))

    assert issue.rule == "os_outdated"


# ── Android patch level ───────────────────────────────────────────────────────

def test_un_correctif_android_trop_ancien_est_signale():
    [issue] = evaluate(AndroidPatchLevelRule(), mobile(Platform.ANDROID, "Android", "14", patch="2026-07-01"))

    assert (issue.rule, issue.severity) == ("android_patch_outdated", "medium")
    assert issue.title == "Android security patch level is 143 days old"


@pytest.mark.parametrize("patch", ["2026-08-23", None, "", "inconnu"])
def test_un_correctif_android_recent_ou_inconnu_ne_produit_rien(patch):
    assert evaluate(AndroidPatchLevelRule(), mobile(Platform.ANDROID, "Android", "14", patch=patch)) == []


def test_le_niveau_de_correctif_ne_concerne_que_android():
    assert evaluate(AndroidPatchLevelRule(), mobile(Platform.IOS, "iOS", "18.7.12", patch="2020-01-01")) == []


# ── Software support ──────────────────────────────────────────────────────────

def test_un_logiciel_dont_la_version_n_est_plus_supportee_est_signale():
    [issue] = evaluate(AppSupportRule(), windows("10.0.26200.7171", InstalledApp("Microsoft Office Professional Plus 2019 - fr-fr", "16.0.10417.20020")))

    assert (issue.rule, issue.severity, issue.subject) == ("app_unsupported", "medium", "office:2019")
    assert issue.title == "Microsoft Office 2019 is no longer supported"


def test_le_delai_de_grace_evite_de_signaler_un_navigateur_tout_juste_remplace():
    just_replaced = windows("10.0.26200.7171", InstalledApp("Google Chrome", "157.0.7390.122"))  # eol 2026-11-17
    long_gone = windows("10.0.26200.7171", InstalledApp("Google Chrome", "154.0.7200.10"))  # eol 2026-10-06

    assert evaluate(AppSupportRule(), just_replaced) == []
    [issue] = evaluate(AppSupportRule(), long_gone)
    assert issue.subject == "chrome:154"


# ── Software updates ──────────────────────────────────────────────────────────

def test_un_logiciel_en_retard_sur_l_editeur_est_signale():
    [issue] = evaluate(AppUpdateRule(), windows("10.0.26200.7171", InstalledApp("Notepad++ (64-bit x64)", "8.9.2")))

    assert (issue.rule, issue.severity, issue.confidence, issue.subject) == ("app_outdated", "low", 1.0, "notepad-plus-plus")
    assert issue.title == "Notepad++ (64-bit x64) is not up to date (8.9.2, 8.9.9.1 available)"
    assert issue.references == ("https://endoflife.date/notepad-plus-plus",)


def test_un_logiciel_inconnu_du_catalogue_est_compare_au_parc():
    late = windows("10.0.26200.7171", InstalledApp("7-Zip 24.07 (x64)", "24.07"))
    fleet = [windows("10.0.26200.7171", InstalledApp("7-Zip 24.08 (x64)", "24.08")) for _ in range(2)]

    [issue] = evaluate(AppUpdateRule(), late, *fleet)

    assert (issue.subject, issue.confidence) == ("7-zip", 0.8)
    assert issue.title == "7-Zip 24.07 (x64) is not up to date (24.07, 24.08 available)"


def test_un_produit_connu_sans_derniere_version_chez_l_editeur_est_compare_au_parc():
    # endoflife.date gives no "latest" for Chrome.
    late = windows("10.0.26200.7171", InstalledApp("Google Chrome", "158.0.7444.50"))
    fleet = [windows("10.0.26200.7171", InstalledApp("Google Chrome", "158.0.7444.59")) for _ in range(2)]

    [issue] = evaluate(AppUpdateRule(), late, *fleet)

    assert (issue.subject, issue.confidence) == ("chrome", 0.8)


def test_un_logiciel_a_jour_ou_sans_version_ne_produit_rien():
    device = windows("10.0.26200.7171", InstalledApp("Notepad++", "8.9.9.1"), InstalledApp("Outil maison", None))

    assert evaluate(AppUpdateRule(), device, device) == []


def test_un_logiciel_hors_support_n_est_pas_signale_en_plus_comme_non_a_jour():
    assert evaluate(AppUpdateRule(), windows("10.0.26200.7171", InstalledApp("Notepad++", "8.8.3"))) == []


def test_une_copie_ancienne_a_cote_de_la_recente_n_est_pas_signalee_comme_retard():
    device = windows("10.0.26200.7171", InstalledApp("Notepad++", "8.9.2"), InstalledApp("Notepad++", "8.9.9.1"))

    assert evaluate(AppUpdateRule(), device) == []


# ── Policy ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "values",
    [{"support_warning_days": -1}, {"app_support_grace_days": -1}, {"android_patch_max_age_days": -1}, {"fleet_min_devices": 0}],
)
def test_une_politique_d_audit_incoherente_est_refusee(values):
    with pytest.raises(ValueError):
        AuditPolicy(**values)


# ── DeviceAuditor ─────────────────────────────────────────────────────────────

def auditor(catalog=None, rules=None) -> DeviceAuditor:
    return DeviceAuditor(rules or default_rules(), lambda: catalog or StaticSupportCatalog(), today=lambda: TODAY)


def test_l_audit_regroupe_les_constats_par_appareil():
    old = windows("10.0.22631.4317", InstalledApp("Notepad++", "8.9.2"))
    fine = windows("10.0.26200.7171")

    outcome = auditor().audit([old, fine])

    assert set(outcome.issues) == {old.external_id}
    assert sorted(issue.rule for issue in outcome.issues[old.external_id]) == ["app_outdated", "os_unsupported"]
    assert outcome.issue_count == 2
    assert outcome.complete


def test_l_audit_signale_les_produits_dont_le_cycle_de_vie_n_a_pas_pu_etre_verifie():
    outcome = auditor(StaticSupportCatalog(unavailable=("windows",))).audit([windows("10.0.22631.4317")])

    assert outcome.unavailable_products == frozenset({"windows"})
    assert not outcome.complete


class ExplodingRule:
    def evaluate(self, device, context):
        if device.name == "PC-BIZARRE":
            raise ValueError("unexpected data")
        return []


def test_une_regle_en_echec_sur_un_appareil_n_empeche_pas_l_audit_des_autres():
    odd = windows("10.0.22631.4317", name="PC-BIZARRE")
    normal = windows("10.0.22631.4317")

    outcome = auditor(rules=[ExplodingRule(), OsSupportRule()]).audit([odd, normal])

    assert set(outcome.issues) == {odd.external_id, normal.external_id}
    assert outcome.rule_errors == 1
    assert not outcome.complete


def test_un_catalogue_neuf_est_utilise_a_chaque_audit():
    created = []

    def factory():
        created.append(StaticSupportCatalog())
        return created[-1]

    audit = DeviceAuditor(default_rules(), factory, today=lambda: TODAY)
    audit.audit([])
    audit.audit([])

    assert len(created) == 2
