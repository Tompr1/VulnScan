"""
API HTTP des sondes : l'administration par un admin global (Root) et les
appels de la sonde elle-même, de l'enrôlement au rapport.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_probe_agent, routes_probes
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.config import settings
from app.core.job_queue import ProbeAwareJobQueue
from app.db import models
from app.probes.gateway import ProbeGateway
from app.scan_jobs.assigner import JobAssigner
from app.scan_jobs.assignment import ScanReport
from app.scan_jobs.repository import SqlScanJobRepository
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.sql_resources import SqlCredentialVault
from tests.fakes import SpyCancellationSignal, SpyJobQueue, finding

pytestmark = pytest.mark.integration

ADMIN_GLOBAL, ADMIN_CLIENT = 1, 2
CLIENT, VOISIN = 1, 2


class Allowlists:
    def policy_for(self, workspace_id):
        return AllowlistPolicy.from_setting("10.0.0.0/8")


class Env:
    def __init__(self, session_factory, db):
        self.session_factory = session_factory
        self.db = db
        self.file = SpyJobQueue()
        self.annulations = SpyCancellationSignal()
        self.app = FastAPI()
        install_validation_error_handler(self.app)
        self.app.include_router(routes_probes.router)
        self.app.include_router(routes_probe_agent.router)

        def test_db():
            with session_factory() as session:
                yield session

        gateway = ProbeGateway(
            session_factory,
            JobAssigner(SqlScanJobRepository(session_factory), lambda ws: SqlCredentialVault(session_factory, ws), Allowlists()),
            self.file, self.annulations, lambda: datetime.now(timezone.utc), timedelta(hours=24),
        )
        self.app.dependency_overrides[get_db] = test_db
        self.app.dependency_overrides[routes_probe_agent.get_probe_gateway] = lambda: gateway
        self.connecte(ADMIN_GLOBAL)
        self.https = TestClient(self.app, base_url="https://platform.example")
        self.http = TestClient(self.app, base_url="http://platform.example")

    def connecte(self, uid):
        self.app.dependency_overrides[require_auth] = lambda: {"uid": uid, "ws": CLIENT, "sub": f"user{uid}@msp.example"}

    def sonde_enrolee(self, workspace_id=CLIENT):
        creee = self.https.post("/probes", json={"workspace_id": workspace_id, "name": "site-paris"}).json()
        reponse = self.https.post("/probe/v1/enroll", json={"token": creee["enrollment"]["token"], "hostname": "probe-01"})
        return creee["id"], {"Authorization": f"Probe {reponse.json()['credential']}", "X-Probe-Version": "0.1.0"}

    def job_soumis(self, job_id, workspace_id=CLIENT):
        self.db.add(models.ScanJob(id=job_id, workspace_id=workspace_id, target="10.0.0.5", profile_id=5,
                                   status="queued", scan_type="internal"))
        self.db.commit()
        ProbeAwareJobQueue(self.session_factory, self.file).enqueue_scan(job_id)


@pytest.fixture
def env(session_factory, db, workspace):
    db.add_all([
        models.User(id=ADMIN_GLOBAL, email="root@msp.example", password_hash="x", is_global_admin=True),
        models.User(id=ADMIN_CLIENT, email="admin@client.example", password_hash="x"),
    ])
    db.flush()
    db.add(models.AccessGrant(user_id=ADMIN_CLIENT, workspace_id=CLIENT, role="admin"))
    db.commit()
    return Env(session_factory, db)


# ── Parcours complet ──────────────────────────────────────────────────────────

def test_un_scan_d_un_client_part_sur_sa_sonde_et_en_revient(env):
    # Arrange : sonde créée par Root, enrôlée, scans internes du client confiés à la sonde.
    probe_id, sonde = env.sonde_enrolee()
    assert env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]}).status_code == 200
    env.job_soumis(20)

    # Act
    prise = env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde)
    progression = env.https.post("/probe/v1/jobs/20/progress", json={"progress": {"pct": 50}}, headers=sonde)
    rapport = ScanReport.succeeded(20, [finding("XSS", severity="high")]).to_dict()
    envoi = env.https.post("/probe/v1/jobs/20/report", json=rapport, headers=sonde)

    # Assert
    assert env.file.scans == [], "le job n'est pas parti vers les workers de la plateforme"
    assert (prise.status_code, prise.json()["job_id"], prise.json()["allowlist"]) == (200, 20, "10.0.0.0/8")
    assert prise.headers["Cache-Control"] == "no-store"
    assert progression.json() == {"cancel": False}
    assert (envoi.status_code, env.file.reports) == (202, [(20, rapport)])
    vue = env.https.get("/probes").json()
    [ligne] = vue["probes"]
    assert (ligne["id"], ligne["status"], ligne["version"], ligne["running_jobs"]) == (probe_id, "online", "0.1.0", 1)


def test_sans_sonde_choisie_les_scans_restent_sur_la_plateforme(env):
    env.job_soumis(20)

    env.db.expire_all()
    assert env.file.scans == [20]
    assert env.db.get(models.ScanJob, 20).runs_on == "platform"


def test_un_type_non_confie_a_la_sonde_reste_sur_la_plateforme(env):
    env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["external"]})

    env.job_soumis(20)

    assert env.file.scans == [20]


def test_sans_job_la_sonde_recoit_204(env):
    _, sonde = env.sonde_enrolee()

    assert env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde).status_code == 204


def test_une_annulation_demandee_est_transmise_a_la_sonde(env):
    _, sonde = env.sonde_enrolee()
    env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]})
    env.job_soumis(20)
    env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde)
    env.annulations.request(20)

    reponse = env.https.post("/probe/v1/jobs/20/progress", json={"progress": {}}, headers=sonde)

    assert reponse.json() == {"cancel": True}


def test_une_sonde_ne_voit_pas_les_jobs_d_un_autre_client(env):
    _, sonde = env.sonde_enrolee(CLIENT)
    env.https.put(f"/probes/clients/{VOISIN}/execution", json={"scan_types": ["internal"]})
    env.job_soumis(21, VOISIN)

    assert env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde).status_code == 204
    assert env.https.post("/probe/v1/jobs/21/report", json=ScanReport.succeeded(21, []).to_dict(),
                          headers=sonde).status_code == 404


def test_un_rapport_est_refuse_quand_la_file_est_indisponible(env):
    _, sonde = env.sonde_enrolee()
    env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]})
    env.job_soumis(20)
    env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde)
    env.file.available = False

    reponse = env.https.post("/probe/v1/jobs/20/report", json=ScanReport.succeeded(20, []).to_dict(), headers=sonde)

    assert reponse.status_code == 503


# ── Canal et identité de la sonde ─────────────────────────────────────────────

def test_l_api_des_sondes_est_refusee_en_http(env):
    _, sonde = env.sonde_enrolee()

    reponse = env.http.post("/probe/v1/heartbeat", json={}, headers=sonde)

    assert reponse.status_code == 403


def test_l_en_tete_x_forwarded_proto_d_un_client_quelconque_est_ignore(env):
    _, sonde = env.sonde_enrolee()

    reponse = env.http.post("/probe/v1/heartbeat", json={}, headers={**sonde, "X-Forwarded-Proto": "https"})

    assert reponse.status_code == 403


def test_le_http_peut_etre_autorise_pour_un_labo(env, monkeypatch):
    _, sonde = env.sonde_enrolee()
    monkeypatch.setattr(settings, "PROBE_REQUIRE_HTTPS", False)

    assert env.http.post("/probe/v1/heartbeat", json={}, headers=sonde).status_code == 200


def test_sans_identifiant_valide_la_sonde_est_refusee(env):
    env.sonde_enrolee()

    for headers in ({}, {"Authorization": "Probe 1.faux"}, {"Authorization": "Bearer jwt"}):
        assert env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=headers).status_code == 401


def test_un_jeton_d_enrolement_inconnu_est_refuse(env):
    reponse = env.https.post("/probe/v1/enroll", json={"token": "x" * 43})

    assert reponse.status_code == 401


def test_une_sonde_revoquee_est_refusee_aussitot(env):
    probe_id, sonde = env.sonde_enrolee()

    env.https.post(f"/probes/{probe_id}/revoke")

    assert env.https.post("/probe/v1/heartbeat", json={}, headers=sonde).status_code == 401
    assert env.https.post(f"/probes/{probe_id}/enrollment").status_code == 409


# ── Référentiel ───────────────────────────────────────────────────────────────

def test_un_jeu_de_donnees_inchange_n_est_pas_renvoye(env, tmp_path):
    _, sonde = env.sonde_enrolee()
    fichier = tmp_path / "kev.json"
    fichier.write_text(json.dumps([{"cve": "CVE-2024-1"}]))
    env.db.add(models.CveDataset(id=1, name="kev", kind="cisa_kev", path=str(fichier)))
    env.db.commit()

    premier = env.https.get("/probe/v1/reference/datasets/cisa_kev", headers=sonde)
    second = env.https.get("/probe/v1/reference/datasets/cisa_kev",
                           headers={**sonde, "If-None-Match": premier.headers["ETag"]})

    assert premier.json() == [[{"cve": "CVE-2024-1"}]]
    assert second.status_code == 304


# ── Administration (Root) ─────────────────────────────────────────────────────

def test_seul_un_admin_global_administre_les_sondes(env):
    env.connecte(ADMIN_CLIENT)

    reponses = [
        env.https.get("/probes"),
        env.https.post("/probes", json={"workspace_id": CLIENT, "name": "x"}),
        env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]}),
    ]

    assert [r.status_code for r in reponses] == [403, 403, 403]


def test_le_jeton_d_enrolement_n_est_montre_qu_a_la_creation(env):
    creee = env.https.post("/probes", json={"workspace_id": CLIENT, "name": "site"}).json()

    liste = env.https.get("/probes").text

    assert creee["status"] == "pending" and len(creee["enrollment"]["token"]) >= 40
    assert creee["enrollment"]["token"] not in liste


def test_un_type_de_scan_qui_ne_peut_pas_aller_sur_une_sonde_est_refuse(env):
    reponse = env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal", "inventory"]})

    assert reponse.status_code == 422


def test_supprimer_une_sonde_garde_l_historique_de_ses_jobs(env):
    probe_id, sonde = env.sonde_enrolee()
    env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]})
    env.job_soumis(20)
    env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde)

    assert env.https.delete(f"/probes/{probe_id}").status_code == 200

    env.db.expire_all()
    assert env.db.get(models.ScanJob, 20).probe_id is None
    assert env.db.get(models.Probe, probe_id) is None
