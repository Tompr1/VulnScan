"""
Support lifecycle: cycles, the endoflife.date catalog and the identification
of OS and applications reported by a fleet manager.
"""
from datetime import date

import httpx
import pytest

from app.inventory.audit.catalog import EndOfLifeDateCatalog
from app.inventory.audit.lifecycle import (
    CatalogUnavailableError,
    SupportCycle,
    is_older,
    is_precise_enough,
    leading_version,
)
from app.inventory.audit.products import identify_app, identify_os
from app.inventory.domain import Device, InstalledApp, Platform
from tests.unit.inventory import eol_fixtures as eol

TODAY = date(2026, 11, 21)


# ── SupportCycle ──────────────────────────────────────────────────────────────

def test_un_cycle_dont_la_date_de_fin_est_passee_n_est_plus_supporte():
    cycle = SupportCycle("11-23h2-w", support_ends_on=date(2025, 11, 11))

    assert cycle.is_unsupported(TODAY)
    assert cycle.days_left(TODAY) == 0


def test_le_dernier_jour_de_support_est_encore_supporte():
    cycle = SupportCycle("14", support_ends_on=TODAY)

    assert not cycle.is_unsupported(TODAY)


def test_le_delai_de_grace_repousse_la_fin_de_support():
    cycle = SupportCycle("157", support_ends_on=date(2026, 11, 17))

    assert cycle.is_unsupported(TODAY)
    assert not cycle.is_unsupported(TODAY, grace_days=14)


def test_un_cycle_sans_date_de_fin_reste_supporte():
    cycle = SupportCycle("26")

    assert not cycle.is_unsupported(TODAY)
    assert cycle.days_left(TODAY) is None


def test_un_cycle_declare_termine_sans_date_n_est_plus_supporte():
    assert SupportCycle("4.4", ended=True).is_unsupported(TODAY)


def test_les_jours_restants_sont_comptes_jusqu_a_la_fin():
    assert SupportCycle("22.04", support_ends_on=date(2026, 12, 21)).days_left(TODAY) == 30


def test_un_cycle_sans_nom_est_refuse():
    with pytest.raises(ValueError):
        SupportCycle(" ")


@pytest.mark.parametrize(
    ("text", "version"),
    [("14.4.1 (23E224)", "14.4.1"), ("Ubuntu 22.04.3 LTS", "22.04.3"), ("14", "14"), ("", None), (None, None), ("Linux", None)],
)
def test_la_version_est_extraite_du_texte_du_gestionnaire(text, version):
    assert leading_version(text) == version


@pytest.mark.parametrize(
    ("installed", "reference", "older"),
    [
        ("17.4.1", "17.7.7", True),
        ("17.7.7", "17.7.7", False),
        ("18.0", "17.7.7", False),
        ("7.4.6.0", "7.4.22", True),  # numeric order, not text order
        ("n/a", "1.0", False),  # unreadable: never reported as older
        (None, "1.0", False),
    ],
)
def test_une_version_n_est_plus_ancienne_que_si_les_deux_sont_lisibles(installed, reference, older):
    assert is_older(installed, reference) is older


@pytest.mark.parametrize(
    ("reference", "installed", "precise"),
    [
        ("10.0.22631", "10.0.22631.4317", False),  # Windows: monthly update missing
        ("14.8.9", "14.4.1", True),
        ("26.7.3", "26.1", True),
        (None, "1.0", False),
    ],
)
def test_une_reference_moins_precise_que_la_version_installee_est_ecartee(reference, installed, precise):
    assert is_precise_enough(reference, installed) is precise


# ── endoflife.date catalog ────────────────────────────────────────────────────

def catalog_answering(handler) -> tuple[EndOfLifeDateCatalog, list[str]]:
    requested = []

    def transport(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        return handler(request)

    return EndOfLifeDateCatalog(httpx.Client(transport=httpx.MockTransport(transport))), requested


def test_le_catalogue_lit_les_cycles_d_un_produit():
    catalog, requested = catalog_answering(lambda request: httpx.Response(200, json=eol.MACOS))

    cycles = catalog.cycles("macos")

    assert requested == ["/api/macos.json"]
    assert [c.name for c in cycles] == ["26", "15", "14", "10.15"]
    assert cycles[2] == SupportCycle("14", support_ends_on=date(2026, 9, 14), latest="14.8.9")
    assert cycles[0].support_ends_on is None and not cycles[0].ended


def test_le_catalogue_traduit_les_champs_d_endoflife_date():
    catalog, _ = catalog_answering(lambda request: httpx.Response(200, json=[
        {"cycle": 8, "eol": True, "latest": 8.1},
        {"cycle": "11-23h2-w", "releaseLabel": "11 23H2 (W)", "eol": "2025-11-11", "latest": "10.0.22631"},
    ]))

    old, windows = catalog.cycles("x")

    assert (old.name, old.ended, old.latest) == ("8", True, "8.1")
    assert (windows.label, windows.support_ends_on) == ("11 23H2 (W)", date(2025, 11, 11))


def test_une_entree_invalide_est_ecartee_sans_perdre_les_autres():
    catalog, _ = catalog_answering(lambda request: httpx.Response(200, json=[
        {"cycle": "", "eol": False}, {"eol": "2020-01-01"}, {"cycle": "2", "eol": "pas une date"}, "texte",
        {"cycle": "3", "eol": False},
    ]))

    assert [c.name for c in catalog.cycles("x")] == ["3"]


def test_chaque_produit_n_est_demande_qu_une_fois():
    catalog, requested = catalog_answering(lambda request: httpx.Response(200, json=eol.IOS))

    catalog.cycles("ios")
    catalog.cycles("ios")

    assert requested == ["/api/ios.json"]


@pytest.mark.parametrize(
    "answer",
    [
        lambda request: httpx.Response(404, text="Not found"),
        lambda request: httpx.Response(200, text="<html>"),
        lambda request: httpx.Response(200, json={"error": "x"}),
    ],
)
def test_une_reponse_inexploitable_rend_le_produit_indisponible(answer):
    catalog, _ = catalog_answering(answer)

    with pytest.raises(CatalogUnavailableError, match="windows"):
        catalog.cycles("windows")


def test_un_echec_reseau_est_memorise_pour_ne_pas_reessayer_a_chaque_appareil():
    def unreachable(request):
        raise httpx.ConnectError("no route to host")

    catalog, requested = catalog_answering(unreachable)

    for _ in range(3):
        with pytest.raises(CatalogUnavailableError, match="unreachable"):
            catalog.cycles("windows")
    assert requested == ["/api/windows.json"]


# ── OS identification ─────────────────────────────────────────────────────────

def device(platform: Platform, os_name: str, os_version: str | None) -> Device:
    return Device("id-1", "PC-01", platform, os_name=os_name, os_version=os_version)


def os_cycle(os_device: Device) -> SupportCycle | None:
    release = identify_os(os_device)
    return release.cycle_in(eol.cycles(eol.ALL[release.product.slug])) if release else None


@pytest.mark.parametrize(
    ("os_version", "cycle"),
    [
        ("10.0.22631.4317", "11-23h2-w"),  # Home/Pro line preferred: Intune gives no edition
        ("10.0.26100.2033", "11-24h2-w"),  # never the LTSC / IoT line sharing the build
        ("10.0.19045.5011", "10-22h2"),  # single line, no edition suffix
        ("10.0.19044.1288", None),  # only LTSC carries this build any more
        ("10.0.99999.1", None),
    ],
)
def test_la_version_de_windows_est_rattachee_a_son_cycle_par_le_build(os_version, cycle):
    found = os_cycle(device(Platform.WINDOWS, "Windows", os_version))

    assert (found.name if found else None) == cycle


@pytest.mark.parametrize(
    ("platform", "os_name", "os_version", "product", "cycle"),
    [
        (Platform.MACOS, "macOS", "14.4.1 (23E224)", "macos", "14"),
        (Platform.MACOS, "macOS", "10.15.7", "macos", "10.15"),
        (Platform.IOS, "iOS", "17.4.1", "ios", "17"),
        (Platform.IOS, "iPadOS", "18.1", "ipados", "18"),
        (Platform.ANDROID, "Android", "12.1", "android", "12.1"),  # longest matching cycle
        (Platform.ANDROID, "AndroidForWork", "13", "android", "13"),
        (Platform.LINUX, "Ubuntu", "22.04.3", "ubuntu", "22.04"),
        (Platform.LINUX, "Linux", "Ubuntu 24.04.1 LTS", "ubuntu", "24.04"),
    ],
)
def test_le_systeme_est_rattache_a_son_produit_et_a_son_cycle(platform, os_name, os_version, product, cycle):
    os_device = device(platform, os_name, os_version)

    assert identify_os(os_device).product.slug == product
    assert os_cycle(os_device).name == cycle


@pytest.mark.parametrize(
    ("platform", "os_name", "os_version"),
    [
        (Platform.LINUX, "Linux", "6.8.0"),  # which distribution's calendar? unknown
        (Platform.OTHER, "ChromeOS", "128.0"),
        (Platform.WINDOWS, "Windows", None),
        (Platform.MACOS, "macOS", "inconnue"),
    ],
)
def test_un_systeme_non_identifiable_n_est_pas_audite(platform, os_name, os_version):
    assert identify_os(device(platform, os_name, os_version)) is None


# ── Application identification ────────────────────────────────────────────────

def app_cycle(name: str, version: str) -> tuple[str, str | None] | None:
    release = identify_app(InstalledApp(name, version))
    if release is None:
        return None
    found = release.cycle_in(eol.cycles(eol.ALL[release.product.slug]))
    return release.product.slug, found.name if found else None


@pytest.mark.parametrize(
    ("name", "version", "expected"),
    [
        ("Google Chrome", "157.0.7390.122", ("chrome", "157")),
        ("Mozilla Firefox (x64 fr)", "160.0.1", ("firefox", "160")),
        ("Mozilla Firefox ESR (x64 en-US)", "140.4.0", ("firefox", "140")),
        ("Notepad++ (64-bit x64)", "8.8.3", ("notepad-plus-plus", "8.8")),
        ("Microsoft Office Professional Plus 2019 - fr-fr", "16.0.10417.20020", ("office", "2019")),
        ("Microsoft Office LTSC Professional Plus 2021 - en-us", "16.0.14332.20800", ("office", "2021-ltsc")),
        ("Google Chrome", "999.0", ("chrome", None)),  # newer than the catalog
    ],
)
def test_une_application_connue_est_rattachee_a_son_produit_et_a_son_cycle(name, version, expected):
    assert app_cycle(name, version) == expected


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("7-Zip 24.08 (x64)", "24.08"),  # not on endoflife.date: fleet comparison only
        ("Google Chrome Beta", "158.0"),
        ("Microsoft 365 Apps for enterprise - fr-fr", "16.0.18129.20158"),
        ("Google Chrome", None),
    ],
)
def test_une_application_inconnue_du_catalogue_ou_sans_version_n_est_pas_identifiee(name, version):
    assert identify_app(InstalledApp(name, version)) is None
