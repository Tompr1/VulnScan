from datetime import datetime, timezone

import httpx
import pytest

from app.inventory.domain import Platform
from app.inventory.intune.graph_client import GraphPermissionError
from app.inventory.intune.source import IntuneSource
from tests.unit.inventory import intune_fixtures as fx
from tests.unit.inventory.graph_fakes import FakeGraph, graph_page
from tests.unit.inventory.source_contract import assert_satisfies_inventory_source_contract

DEVICES = "/v1.0/deviceManagement/managedDevices"
APPS = "/v1.0/deviceManagement/detectedApps"
NOW = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)


def fake_intune(devices=(fx.WINDOWS_PC, fx.IPHONE), apps=(fx.FIREFOX, fx.SEVEN_ZIP), app_devices=None):
    app_devices = app_devices or {"app-firefox": [fx.WINDOWS_PC["id"]], "app-7zip": [fx.WINDOWS_PC["id"]]}
    routes = {("GET", DEVICES): graph_page(devices), ("GET", APPS): graph_page(apps)}
    for app_id, device_ids in app_devices.items():
        routes[("GET", f"{APPS}/{app_id}/managedDevices")] = graph_page([{"id": d} for d in device_ids])
    return FakeGraph(routes)


def source(graph: FakeGraph) -> IntuneSource:
    return IntuneSource(graph.client(), clock=lambda: NOW)


def test_la_source_intune_respecte_le_contrat_des_sources_d_inventaire():
    assert_satisfies_inventory_source_contract(source(fake_intune()))


def test_un_appareil_intune_est_converti_avec_toutes_ses_informations():
    pc = source(fake_intune()).collect().devices[0]

    assert (pc.external_id, pc.name, pc.platform, pc.os_version) == (fx.WINDOWS_PC["id"], "PC-COMPTA-04", Platform.WINDOWS, "10.0.22631.4317")
    assert (pc.model, pc.manufacturer, pc.user_principal_name) == ("Latitude 5440", "Dell Inc.", "j.martin@contoso.onmicrosoft.com")
    assert (pc.compliance_state, pc.is_encrypted, pc.ownership) == ("compliant", True, "company")
    assert pc.last_check_in_at == datetime(2026, 11, 20, 8, 15, tzinfo=timezone.utc)


def test_les_applications_sont_rattachees_aux_appareils_qui_les_ont():
    pc, iphone = source(fake_intune()).collect().devices

    assert sorted((a.name, a.version) for a in pc.apps) == [("7-Zip 19.00 (x64)", "19.00"), ("Mozilla Firefox (x64 fr)", "128.0.3")]
    assert iphone.apps == ()


def test_une_application_installee_nulle_part_ne_coute_aucune_requete():
    graph = fake_intune(apps=(fx.FIREFOX, fx.UNUSED_APP))

    source(graph).collect()

    assert not any("app-unused" in r.url.path for r in graph.requests)


def test_un_appareil_jamais_synchronise_n_a_pas_de_date_de_synchro():
    device = source(fake_intune(devices=(fx.ANDROID_NEVER_SYNCED,))).collect().devices[0]

    assert (device.platform, device.security_patch_level, device.last_check_in_at) == (Platform.ANDROID, "2026-09-01", None)


def test_les_elements_invalides_sont_ecartes_et_comptes_sans_bloquer_la_collecte():
    snapshot = source(fake_intune(devices=(fx.WINDOWS_PC, fx.INVALID_DEVICE), apps=(fx.FIREFOX, fx.INVALID_APP))).collect()

    assert [d.name for d in snapshot.devices] == ["PC-COMPTA-04"]
    assert (snapshot.skipped_devices, snapshot.skipped_apps) == (1, 1)


def test_seuls_les_champs_utiles_sont_demandes_a_graph():
    graph = fake_intune()

    source(graph).collect()

    selected = graph.graph_calls()[0].url.params["$select"].split(",")
    assert {"deviceName", "osVersion", "complianceState", "lastSyncDateTime"} <= set(selected)
    assert "azureADDeviceId" not in selected


def test_le_test_de_connexion_signale_une_permission_manquante():
    graph = FakeGraph({("GET", DEVICES): httpx.Response(403, json={"error": {"message": "Forbidden"}})})

    with pytest.raises(GraphPermissionError):
        source(graph).check_access()
