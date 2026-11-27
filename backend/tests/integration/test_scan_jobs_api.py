"""
HTTP tests of the /scan routes: real FastAPI routing, validation and
SQLAlchemy queries on SQLite; only authentication, the task queue and the
cancellation signal are replaced.
"""
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.routes_scan import get_cancellation_signal, router
from app.core.auth import require_auth
from app.core.job_queue import get_job_queue
from app.db import models
from tests.fakes import SpyCancellationSignal, SpyJobQueue

pytestmark = pytest.mark.integration


@pytest.fixture
def queue():
    return SpyJobQueue()


@pytest.fixture
def cancellation():
    return SpyCancellationSignal()


@pytest.fixture
def claims(workspace, session_de):
    return session_de(1, "analyst")


@pytest.fixture
def client(session_factory, workspace, queue, cancellation, claims, sonde_en_ligne):
    sonde_en_ligne(1)  # internal scans run on the client's probe only
    app = FastAPI()
    app.include_router(router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[require_auth] = lambda: claims
    app.dependency_overrides[get_job_queue] = lambda: queue
    app.dependency_overrides[get_cancellation_signal] = lambda: cancellation
    return TestClient(app)


def stored_job(db, job_id) -> models.ScanJob:
    db.expire_all()
    return db.get(models.ScanJob, job_id)


def test_creer_un_scan_l_enregistre_et_le_met_en_file(client, queue, db):
    # Act
    response = client.post("/scan/jobs", json={"target": "10.0.0.5", "profile_id": 5, "scan_type": "external"})

    # Assert
    assert response.status_code == 200
    job_id = response.json()["id"]
    assert queue.scans == [job_id]
    job = stored_job(db, job_id)
    assert (job.status, job.scan_type, job.workspace_id, job.target) == ("queued", "external", 1, "10.0.0.5")


def test_une_demande_invalide_renvoie_422_avec_toutes_les_erreurs(client, queue):
    response = client.post("/scan/jobs", json={"target": "", "profile_id": "x", "scan_type": "all"})

    assert response.status_code == 422
    fields = {error["loc"][-1] for error in response.json()["detail"]}
    assert fields == {"target", "profile_id", "scan_type"}
    assert queue.scans == []


def test_un_profil_d_un_autre_workspace_est_introuvable(client, queue):
    response = client.post("/scan/jobs", json={"target": "10.0.0.5", "profile_id": 6})

    assert response.status_code == 404
    assert queue.scans == []


def test_un_dossier_d_actifs_inconnu_est_refuse(client):
    response = client.post("/scan/jobs", json={"target": "10.0.0.5", "profile_id": 5, "asset_id": 77})

    assert response.status_code == 400


def test_si_la_file_est_indisponible_le_job_est_marque_en_echec(client, queue, db):
    queue.available = False

    response = client.post("/scan/jobs", json={"target": "10.0.0.5", "profile_id": 5})

    assert response.status_code == 503
    job = db.query(models.ScanJob).one()
    assert job.status == "failed"
    assert json.loads(job.meta_json)["error_type"] == "queue"


def test_l_authentification_web_ephemere_est_transmise_au_worker(client, db):
    body = {
        "target": "https://app.local",
        "profile_id": 5,
        "web_auth": {"type": "form", "login_url": "/login", "credential_id": 9},
        "web_auth_credential_ephemeral": True,
    }

    job_id = client.post("/scan/jobs", json=body).json()["id"]

    assert json.loads(stored_job(db, job_id).meta_json) == {
        "web_auth": {"type": "form", "login_url": "/login", "credential_id": 9},
        "web_auth_credential_ephemeral": True,
    }


def test_un_lecteur_ne_peut_pas_lancer_de_scan(client, claims, session_de):
    claims.update(session_de(1, "viewer"))

    response = client.post("/scan/jobs", json={"target": "10.0.0.5", "profile_id": 5})

    assert response.status_code == 403


def test_relancer_un_scan_cree_un_nouveau_job_identique(client, queue, db):
    original = client.post("/scan/jobs", json={"target": "10.0.0.5", "profile_id": 5, "scan_type": "external"}).json()["id"]

    response = client.post(f"/scan/jobs/{original}/rescan")

    new_job = stored_job(db, response.json()["id"])
    assert (new_job.target, new_job.scan_type, new_job.profile_id) == ("10.0.0.5", "external", 5)
    assert queue.scans == [original, new_job.id]


def test_annuler_un_scan_en_file_l_annule_immediatement_et_previent_le_worker(client, cancellation, db):
    job_id = client.post("/scan/jobs", json={"target": "10.0.0.5", "profile_id": 5}).json()["id"]

    response = client.post(f"/scan/jobs/{job_id}/cancel")

    assert response.json()["status"] == "cancelled"
    assert cancellation.requested == [job_id]
    assert stored_job(db, job_id).status == "cancelled"


def test_un_profil_peut_etre_cree_avec_une_selection_en_objet_json(client, db):
    response = client.post("/scan/profiles", json={"name": "Web", "plugin_selection_json": {"web.headers": True}})

    profile = db.get(models.Profile, response.json()["id"])
    assert json.loads(profile.plugin_selection_json) == {"web.headers": True}


def test_modifier_le_nom_d_un_profil_ne_touche_pas_a_sa_selection(client, db):
    db.get(models.Profile, 5).plugin_selection_json = '{"keep": true}'
    db.commit()

    client.put("/scan/profiles/5", json={"name": "Renamed"})

    db.expire_all()
    profile = db.get(models.Profile, 5)
    assert (profile.name, profile.plugin_selection_json) == ("Renamed", '{"keep": true}')


def test_une_planification_ponctuelle_est_programmee_a_sa_date(client, db):
    body = {"target": "10.0.0.5", "profile_id": 5, "schedule_type": "custom", "custom_datetime": "2026-03-10T14:30:00Z", "repeat": False}

    response = client.post("/scan/schedules", json=body)

    assert response.status_code == 200
    assert response.json()["next_run_at"].startswith("2026-03-10T14:30:00")


def test_masquer_un_constat_sans_empreinte_est_refuse(client):
    assert client.post("/scan/suppress", json={"reason": "noise"}).status_code == 422
