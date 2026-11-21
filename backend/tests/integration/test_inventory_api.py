"""
HTTP tests of /inventory: real routing, validation and SQL on SQLite; only
authentication, the job queue and Microsoft Graph are replaced.
"""
import json
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.routes_inventory import get_inventory_read_model, get_inventory_source_factory, router
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.crypto import decrypt_str
from app.core.job_queue import get_job_queue
from app.db import models
from app.inventory.collector import InventoryCollector
from app.inventory.domain import Device, InstalledApp, InventorySnapshot, Platform
from app.inventory.intune.graph_client import GraphAuthError
from app.inventory.repository import SqlInventoryReadModel, SqlInventoryRepository
from app.inventory.scheduling import queue_due_syncs
from app.inventory.sync import InventorySync
from app.scan_jobs.submission import ScanJobSubmission
from tests.fakes import SpyJobQueue
from tests.unit.inventory import intune_fixtures as fx
from tests.unit.inventory.test_intune_source import fake_intune

pytestmark = pytest.mark.integration

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
NEW_CONNECTION = {"name": "Tenant de test", "tenant_id": TENANT, "client_id": CLIENT, "client_secret": "s3cr3t~value"}


class StubSource:
    def __init__(self, error=None):
        self.error = error
        self.credentials = None

    def __call__(self, credentials):
        self.credentials = credentials
        return self

    name = "intune"

    def check_access(self):
        if self.error:
            raise self.error


@pytest.fixture
def queue():
    return SpyJobQueue()


@pytest.fixture
def source():
    return StubSource()


@pytest.fixture
def claims():
    return {"ws": 1, "uid": None, "sub": "admin@corp.local", "role": "admin"}


@pytest.fixture
def client(session_factory, workspace, queue, source, claims):
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides.update({
        get_db: test_db,
        require_auth: lambda: claims,
        get_job_queue: lambda: queue,
        get_inventory_source_factory: lambda: source,
        get_inventory_read_model: lambda: SqlInventoryReadModel(session_factory),
    })
    return TestClient(app)


def create(client, **overrides):
    response = client.post("/inventory/connections", json={**NEW_CONNECTION, **overrides})
    assert response.status_code == 201, response.text
    return response.json()


def test_une_connexion_intune_est_creee_sans_jamais_renvoyer_le_secret(client, db):
    created = create(client)

    stored = db.get(models.InventoryConnection, created["id"])
    assert "client_secret" not in created and created["has_client_secret"] is True
    assert stored.client_secret_enc != "s3cr3t~value"
    assert decrypt_str(stored.client_secret_enc) == "s3cr3t~value"
    assert (created["tenant_id"], created["sync_frequency"]) == (TENANT, "daily")


def test_une_connexion_invalide_est_refusee_avec_toutes_ses_erreurs_sans_reveler_le_secret(client):
    response = client.post("/inventory/connections", json={
        "name": " ", "tenant_id": "pas-un-uuid", "client_id": CLIENT, "client_secret": "court", "sync_frequency": "hourly", "extra": 1,
    })

    assert response.status_code == 422
    assert {e["loc"][-1] for e in response.json()["detail"]} == {"name", "tenant_id", "client_secret", "sync_frequency", "extra"}
    assert "court" not in response.text


def test_un_analyste_ne_peut_pas_configurer_de_connexion(client, claims):
    claims["role"] = "analyst"

    assert client.post("/inventory/connections", json=NEW_CONNECTION).status_code == 403


def test_modifier_une_connexion_sans_secret_conserve_le_secret_existant(client, db):
    created = create(client)

    client.put(f"/inventory/connections/{created['id']}", json={"name": "Renommée", "sync_frequency": "weekly"})

    db.expire_all()
    stored = db.get(models.InventoryConnection, created["id"])
    assert (stored.name, stored.sync_frequency, decrypt_str(stored.client_secret_enc)) == ("Renommée", "weekly", "s3cr3t~value")


def test_le_test_de_connexion_utilise_les_identifiants_dechiffres(client, source):
    created = create(client)

    response = client.post(f"/inventory/connections/{created['id']}/test")

    assert response.json()["ok"] is True
    assert (source.credentials.tenant_id, source.credentials.client_secret) == (TENANT, "s3cr3t~value")


def test_un_echec_de_connexion_renvoie_le_message_actionnable(client, source):
    created = create(client)
    source.error = GraphAuthError("Entra ID refused the credentials: the client secret is wrong.")

    response = client.post(f"/inventory/connections/{created['id']}/test")

    assert response.status_code == 400
    assert "client secret is wrong" in response.json()["detail"]


def test_lancer_une_synchro_met_en_file_un_job_d_inventaire(client, queue, db):
    created = create(client)

    response = client.post(f"/inventory/connections/{created['id']}/sync")

    assert response.status_code == 202
    job = db.get(models.ScanJob, response.json()["job_id"])
    assert (job.scan_type, job.profile_id, job.target) == ("inventory", None, "intune:Tenant de test")
    assert json.loads(job.meta_json) == {"inventory_connection_id": created["id"]}
    assert queue.scans == [job.id]
    db.expire_all()
    assert db.get(models.InventoryConnection, created["id"]).last_sync_status == "queued"


def test_une_synchro_impossible_a_mettre_en_file_renvoie_503(client, queue):
    created = create(client)
    queue.available = False

    assert client.post(f"/inventory/connections/{created['id']}/sync").status_code == 503


def test_la_connexion_d_un_autre_workspace_est_introuvable(client, claims):
    created = create(client)
    claims["ws"] = 2

    assert client.post(f"/inventory/connections/{created['id']}/sync").status_code == 404


def seed_inventory(session_factory, connection_id):
    snapshot = InventorySnapshot("intune", (
        Device("d1", "PC-COMPTA-04", Platform.WINDOWS, os_name="Windows", os_version="10.0.22631.4317",
               apps=(InstalledApp("Google Chrome", "128.0"),)),
        Device("d2", "iPhone de J. Martin", Platform.IOS, os_name="iOS", os_version="16.7.10"),
    ), datetime(2026, 11, 21, tzinfo=timezone.utc))
    InventorySync(SqlInventoryRepository(session_factory)).apply(connection_id, 1, snapshot)


def test_la_liste_et_la_fiche_d_un_appareil_sont_disponibles(client, session_factory):
    created = create(client)
    seed_inventory(session_factory, created["id"])

    devices = client.get("/inventory/devices", params={"platform": "windows"}).json()
    detail = client.get(f"/inventory/devices/{devices[0]['id']}").json()

    assert [d["name"] for d in devices] == ["PC-COMPTA-04"]
    assert detail["apps"] == [{"name": "Google Chrome", "version": "128.0", "publisher": None}]
    assert detail["changes"][0]["kind"] == "device_enrolled"


def test_une_plateforme_inconnue_dans_le_filtre_est_refusee(client):
    assert client.get("/inventory/devices", params={"platform": "amiga"}).status_code == 422


def test_un_appareil_inexistant_renvoie_404(client):
    assert client.get("/inventory/devices/999").status_code == 404


def test_supprimer_une_connexion_supprime_ses_appareils(client, session_factory, db):
    created = create(client)
    seed_inventory(session_factory, created["id"])

    response = client.delete(f"/inventory/connections/{created['id']}")

    assert response.json()["deleted_devices"] == 2
    assert db.query(models.InventoryDeviceApp).count() == db.query(models.InventoryDevice).count() == 0


def test_la_collecte_intune_de_bout_en_bout_stocke_l_inventaire_et_le_statut(client, session_factory, db):
    # Arrange: a connection, and Microsoft Graph replaced by a fake tenant
    created = create(client)
    graph = fake_intune()
    from app.inventory.intune.source import IntuneSource

    collector = InventoryCollector(session_factory, source_factory=lambda creds: IntuneSource(graph.client()))

    # Act
    result = collector.collect(created["id"], workspace_id=1)

    # Assert
    db.expire_all()
    connection = db.get(models.InventoryConnection, created["id"])
    assert (result.devices, result.apps) == (2, 2)
    assert (connection.last_sync_status, connection.last_sync_message) == ("ok", result.summary())
    assert {d.name for d in db.query(models.InventoryDevice)} == {fx.WINDOWS_PC["deviceName"], fx.IPHONE["deviceName"]}


def test_un_echec_de_collecte_est_enregistre_sur_la_connexion(client, session_factory, db):
    created = create(client)

    def failing_source(credentials):
        raise GraphAuthError("Entra ID refused the credentials: the client secret has expired.")

    with pytest.raises(GraphAuthError):
        InventoryCollector(session_factory, source_factory=failing_source).collect(created["id"], workspace_id=1)

    db.expire_all()
    connection = db.get(models.InventoryConnection, created["id"])
    assert connection.last_sync_status == "error" and "expired" in connection.last_sync_message


def test_la_planification_met_en_file_les_connexions_dues_une_seule_fois(client, session_factory, queue, db):
    # Arrange
    daily = create(client, name="Quotidienne")
    create(client, name="Manuelle", sync_frequency="manual")
    now = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)

    def queue_sync(session, connection):
        ScanJobSubmission(session, queue).submit_inventory(connection, None, now)

    # Act
    first = queue_due_syncs(session_factory, queue_sync, now)
    second = queue_due_syncs(session_factory, queue_sync, now)

    # Assert
    assert (first, second) == (1, 0)
    job = db.query(models.ScanJob).one()
    assert json.loads(job.meta_json) == {"inventory_connection_id": daily["id"]}
