from datetime import datetime, timedelta, timezone

import pytest

from app.db import models
from app.inventory.domain import Device, InstalledApp, InventorySnapshot, Platform
from app.inventory.repository import SqlInventoryReadModel, SqlInventoryRepository
from app.inventory.sync import InventorySync

pytestmark = pytest.mark.integration

DAY1 = datetime(2026, 11, 20, 6, 0, tzinfo=timezone.utc)
DAY2 = DAY1 + timedelta(days=1)


@pytest.fixture
def connection(db, workspace):
    row = models.InventoryConnection(workspace_id=1, name="Tenant test", tenant_id="t", client_id="c", client_secret_enc="x")
    other = models.InventoryConnection(workspace_id=2, name="Other tenant", tenant_id="t", client_id="c", client_secret_enc="x")
    db.add_all([row, other])
    db.commit()
    return row.id, other.id


def pc(external_id="d1", name="PC-COMPTA-04", os_version="10.0.22631.4317", apps=(("Google Chrome", "127.0"),), platform=Platform.WINDOWS,
       user="j.martin@contoso.com"):
    return Device(external_id, name, platform, os_name="Windows", os_version=os_version, user_principal_name=user,
                  serial_number=f"SN-{external_id}", last_check_in_at=DAY1, apps=tuple(InstalledApp(n, v) for n, v in apps))


def sync(session_factory, connection_id, devices, at, workspace_id=1):
    snapshot = InventorySnapshot("intune", tuple(devices), at)
    return InventorySync(SqlInventoryRepository(session_factory)).apply(connection_id, workspace_id, snapshot)


def test_un_inventaire_enregistre_est_relu_a_l_identique(session_factory, connection):
    sync(session_factory, connection[0], [pc()], DAY1)

    devices = SqlInventoryRepository(session_factory).active_devices(connection[0])

    assert devices["d1"] == pc()
    assert [(a.name, a.version) for a in devices["d1"].apps] == [("Google Chrome", "127.0")]


def test_la_deuxieme_synchro_met_a_jour_l_appareil_et_journalise_les_changements(session_factory, connection, db):
    sync(session_factory, connection[0], [pc()], DAY1)

    result = sync(session_factory, connection[0], [pc(os_version="10.0.22631.4460", apps=[("Google Chrome", "128.0")])], DAY2)

    detail = SqlInventoryReadModel(session_factory).device_detail(1, db.query(models.InventoryDevice).one().id)
    assert result.changes == 2
    assert detail["os_version"] == "10.0.22631.4460"
    assert [a["version"] for a in detail["apps"]] == ["128.0"]
    assert {(c["kind"], c["before"], c["after"]) for c in detail["changes"]} >= {
        ("os_updated", "10.0.22631.4317", "10.0.22631.4460"), ("app_updated", "127.0", "128.0")}


def test_un_appareil_disparu_est_marque_retire_mais_garde_son_historique(session_factory, connection, db):
    sync(session_factory, connection[0], [pc("d1"), pc("d2", name="PC-02")], DAY1)

    sync(session_factory, connection[0], [pc("d1")], DAY2)

    removed = db.query(models.InventoryDevice).filter_by(external_id="d2").one()
    assert removed.removed_at.replace(tzinfo=timezone.utc) == DAY2
    assert [d["name"] for d in SqlInventoryReadModel(session_factory).list_devices(1)] == ["PC-COMPTA-04"]
    assert "d2" not in SqlInventoryRepository(session_factory).active_devices(connection[0])


def test_un_appareil_qui_revient_est_reactive(session_factory, connection, db):
    sync(session_factory, connection[0], [pc("d1")], DAY1)
    sync(session_factory, connection[0], [], DAY2)

    sync(session_factory, connection[0], [pc("d1")], DAY2 + timedelta(days=1))

    assert db.query(models.InventoryDevice).filter_by(external_id="d1").one().removed_at is None


def test_la_liste_des_appareils_se_filtre_par_plateforme_et_recherche(session_factory, connection):
    sync(session_factory, connection[0], [
        pc("d1"), pc("d2", name="iPhone de J. Martin", platform=Platform.IOS, apps=()),
        pc("d3", name="PC-RH-01", user="a.durand@contoso.com", apps=(("7-Zip", "24.08"), ("VLC", "3.0.21"))),
    ], DAY1)
    read = SqlInventoryReadModel(session_factory)

    assert [d["name"] for d in read.list_devices(1, platform="ios")] == ["iPhone de J. Martin"]
    assert [d["name"] for d in read.list_devices(1, search="DURAND")] == ["PC-RH-01"]
    assert [d["app_count"] for d in read.list_devices(1, search="pc-rh")] == [2]


def test_un_appareil_d_un_autre_workspace_est_invisible(session_factory, connection, db):
    sync(session_factory, connection[1], [pc("x1")], DAY1, workspace_id=2)
    other_device = db.query(models.InventoryDevice).one().id

    read = SqlInventoryReadModel(session_factory)

    assert read.list_devices(1) == []
    assert read.device_detail(1, other_device) is None
