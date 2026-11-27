"""La découverte d'un réseau est confiée à la sonde du client : la page la
lance, la suit et peut l'annuler ; sans sonde, elle est refusée."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_analytics
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.config import settings
from app.core.workspace_settings import set_client_allowlist
from app.db import models
from app.discovery.jobs import close_stale_discoveries

pytestmark = pytest.mark.integration

MAINTENANT = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def client(session_factory, db, workspace, session_de, monkeypatch):
    monkeypatch.setattr(settings, "ALLOWLIST", "")  # aucune allowlist : tout le privé est permis
    db.add(models.Probe(id=40, workspace_id=1, name="sonde-paris", status="active"))
    db.add(models.Asset(id=70, workspace_id=1, name="Routeur box"))
    db.add(models.Asset(id=71, workspace_id=1, name="Imprimante"))
    db.add(models.AssetTarget(id=80, workspace_id=1, asset_id=70, target="192.168.3.1"))
    db.add(models.ScanJob(id=81, workspace_id=1, target="192.168.3.5", profile_id=5, asset_id=71))
    db.add(models.AssetTarget(id=82, workspace_id=2, asset_id=70, target="192.168.3.9"))  # autre client
    db.commit()

    claims = session_de(1, "admin")
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_analytics.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides.update({get_db: test_db, require_auth: lambda: claims})
    return TestClient(app, raise_server_exceptions=False)


def _decouverte(db, ws=1, status="done", hosts=(), **extra):
    job = models.DiscoveryJob(
        workspace_id=ws, network_range="192.168.3.0/24", status=status, total=254,
        hosts_json=json.dumps(list(hosts)), **extra,
    )
    db.add(job)
    db.commit()
    return job


# ── Lancement ────────────────────────────────────────────────────────────────

def test_a_network_discovery_is_queued_for_the_client_s_probe(client, db):
    reponse = client.post("/analytics/discover", json={"network_range": "192.168.3.7/24"})

    assert reponse.status_code == 200, reponse.text
    corps = reponse.json()
    assert (corps["status"], corps["network_range"], corps["total"], corps["probed"]) == ("queued", "192.168.3.0/24", 254, 0)
    assert corps["probe_id"] is None  # pas encore prise


@pytest.mark.parametrize("statut", ["pending", "revoked"])
def test_without_an_active_probe_discovery_is_refused(client, db, statut):
    db.get(models.Probe, 40).status = statut
    db.commit()

    reponse = client.post("/analytics/discover", json={"network_range": "192.168.3.0/24"})

    assert reponse.status_code == 409
    assert "no scan probe" in reponse.json()["detail"]
    assert db.query(models.DiscoveryJob).count() == 0


def test_another_client_s_probe_does_not_count(client, db):
    db.get(models.Probe, 40).workspace_id = 2
    db.commit()

    assert client.post("/analytics/discover", json={"network_range": "192.168.3.0/24"}).status_code == 409


def test_a_range_outside_the_client_s_allowlist_is_refused(client, db):
    set_client_allowlist(db, 1, ["192.168.3.0/24"])

    dedans = client.post("/analytics/discover", json={"network_range": "192.168.3.128/25"})
    dehors = client.post("/analytics/discover", json={"network_range": "192.168.0.0/16"})

    assert dedans.status_code == 200, dedans.text
    assert dehors.status_code == 400
    assert "outside this client's allowlist" in dehors.json()["detail"]


def test_a_client_runs_one_discovery_at_a_time(client, db):
    _decouverte(db, status="running")

    reponse = client.post("/analytics/discover", json={"network_range": "10.0.0.0/24"})

    assert reponse.status_code == 409
    assert "already running" in reponse.json()["detail"]


def test_another_client_s_discovery_does_not_block(client, db):
    _decouverte(db, ws=2, status="running")

    assert client.post("/analytics/discover", json={"network_range": "10.0.0.0/24"}).status_code == 200


def test_a_public_range_is_refused_before_any_job(client, db):
    reponse = client.post("/analytics/discover", json={"network_range": "8.8.8.0/24"})

    assert reponse.status_code == 400
    assert db.query(models.DiscoveryJob).count() == 0


# ── Suivi ────────────────────────────────────────────────────────────────────

def test_hosts_already_on_an_asset_are_flagged_with_it(client, db):
    job = _decouverte(db, hosts=[
        {"ip": "192.168.3.1", "hostname": None},
        {"ip": "192.168.3.5", "hostname": None},
        {"ip": "192.168.3.9", "hostname": None},
        {"ip": "192.168.3.10", "hostname": "nouveau.lan"},
    ])

    par_ip = {h["ip"]: h for h in client.get(f"/analytics/discover/jobs/{job.id}").json()["hosts"]}

    assert (par_ip["192.168.3.1"]["asset_id"], par_ip["192.168.3.1"]["asset_name"]) == (70, "Routeur box")
    assert (par_ip["192.168.3.5"]["asset_id"], par_ip["192.168.3.5"]["asset_name"]) == (71, "Imprimante")
    assert par_ip["192.168.3.10"]["asset_id"] is None
    assert par_ip["192.168.3.9"]["asset_id"] is None  # cible d'un autre client


def test_a_host_added_after_the_run_shows_as_known(client, db):
    job = _decouverte(db, hosts=[{"ip": "192.168.3.10", "hostname": None}])
    db.add(models.AssetTarget(workspace_id=1, asset_id=70, target="192.168.3.10"))
    db.commit()

    hote = client.get(f"/analytics/discover/jobs/{job.id}").json()["hosts"][0]

    assert hote["asset_id"] == 70


def test_latest_discoveries_come_first_and_stay_in_their_client(client, db):
    ancienne = _decouverte(db)
    _decouverte(db, ws=2)
    recente = _decouverte(db)

    assert [j["id"] for j in client.get("/analytics/discover/jobs").json()] == [recente.id, ancienne.id]


def test_a_discovery_of_another_client_is_not_found(client, db):
    job = _decouverte(db, ws=2, status="running")

    assert client.get(f"/analytics/discover/jobs/{job.id}").status_code == 404
    assert client.post(f"/analytics/discover/jobs/{job.id}/cancel").status_code == 404
    db.refresh(job)
    assert not job.cancel_requested


# ── Annulation ───────────────────────────────────────────────────────────────

def test_cancelling_a_queued_discovery_ends_it_at_once(client, db):
    job = _decouverte(db, status="queued")

    corps = client.post(f"/analytics/discover/jobs/{job.id}/cancel").json()

    assert corps["status"] == "cancelled" and corps["finished_at"]


def test_cancelling_a_running_discovery_asks_the_probe_to_stop(client, db):
    job = _decouverte(db, status="running", probe_id=40)

    corps = client.post(f"/analytics/discover/jobs/{job.id}/cancel").json()

    assert (corps["status"], corps["cancel_requested"]) == ("running", True)


# ── Découvertes que plus aucune sonde ne terminera ──────────────────────────

def test_a_discovery_whose_probe_stopped_reporting_is_closed_with_its_hosts(db, workspace):
    job = _decouverte(db, status="running", started_at=MAINTENANT - timedelta(hours=2),
                      hosts=[{"ip": "192.168.3.2", "hostname": None}])
    recente = _decouverte(db, status="running", started_at=MAINTENANT - timedelta(minutes=5))

    fermees = close_stale_discoveries(db, MAINTENANT, running_after=timedelta(hours=1), unclaimed_after=timedelta(minutes=30))

    db.refresh(job), db.refresh(recente)
    assert fermees == 1
    assert job.status == "failed" and "stopped reporting" in job.error
    assert len(json.loads(job.hosts_json)) == 1
    assert recente.status == "running"


def test_a_discovery_no_probe_took_is_closed_with_a_hint(db, workspace):
    job = _decouverte(db, status="queued", created_at=MAINTENANT - timedelta(hours=1))
    recente = _decouverte(db, status="queued", created_at=MAINTENANT - timedelta(minutes=5))

    close_stale_discoveries(db, MAINTENANT, running_after=timedelta(hours=1), unclaimed_after=timedelta(minutes=30))

    db.refresh(job), db.refresh(recente)
    assert job.status == "failed" and "online and up to date" in job.error
    assert recente.status == "queued"
