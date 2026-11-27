"""
API HTTP des sondes : l'administration par un admin global (Root) et les
appels de la sonde elle-même, de l'enrôlement au rapport.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_probe_agent, routes_probes, routes_scan
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
        self.app.include_router(routes_scan.router)

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


# ── Exploitation : journal, versions, où un scan a tourné ─────────────────────

DIGEST = "ghcr.io/msp/v0cday-probe@sha256:" + "a" * 64
NEW_DIGEST = "ghcr.io/msp/v0cday-probe@sha256:" + "b" * 64


def test_le_journal_d_une_sonde_raconte_sa_vie_du_plus_recent_au_plus_ancien(env):
    # Arrange : créée, enrôlée, un job pris et rendu, puis révoquée.
    probe_id, sonde = env.sonde_enrolee()
    env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]})
    env.job_soumis(20)
    env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde)
    env.https.post("/probe/v1/jobs/20/report", json=ScanReport.succeeded(20, [finding("XSS")]).to_dict(), headers=sonde)
    env.https.post(f"/probes/{probe_id}/revoke")

    # Act
    journal = env.https.get(f"/probes/{probe_id}/events").json()

    # Assert
    assert [e["kind"] for e in journal] == ["revoked", "report_received", "job_claimed", "enrolled", "created"]
    assert journal[1]["detail"] == "1 findings" and journal[1]["job_id"] == 20
    assert journal[2]["detail"] == "internal scan of 10.0.0.5"
    assert "host=probe-01" in journal[3]["detail"]


def test_la_sonde_declare_son_image_et_root_voit_si_elle_est_a_jour(env, monkeypatch):
    probe_id, sonde = env.sonde_enrolee()
    monkeypatch.setattr(settings, "PROBE_IMAGE", NEW_DIGEST)

    env.https.post("/probe/v1/heartbeat", json={"image": DIGEST, "appliance_version": "1.0.0"}, headers=sonde)
    avant = env.https.get("/probes").json()["probes"][0]
    env.https.post("/probe/v1/heartbeat", json={"image": NEW_DIGEST}, headers=sonde)
    apres = env.https.get("/probes").json()["probes"][0]

    assert (avant["image"], avant["appliance_version"], avant["image_status"]) == (DIGEST, "1.0.0", "update_pending")
    assert (apres["image"], apres["image_status"]) == (NEW_DIGEST, "current")
    changement = env.https.get(f"/probes/{probe_id}/events").json()[0]
    assert (changement["kind"], changement["detail"]) == ("image_changed", f"{DIGEST} -> {NEW_DIGEST}")


@pytest.mark.parametrize(("running", "desired", "status"), [
    (None, None, "unmanaged"), (DIGEST, None, "unmanaged"), (None, DIGEST, "unknown"),
    (DIGEST, DIGEST, "current"), (DIGEST, NEW_DIGEST, "update_pending"),
])
def test_l_etat_de_l_image_compare_ce_qui_tourne_a_ce_qui_est_demande(running, desired, status):
    assert routes_probes.image_status(running, desired) == status


def test_le_client_voit_sur_quelle_sonde_ses_scans_ont_tourne(env):
    _, sonde = env.sonde_enrolee()
    env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]})
    env.job_soumis(20)
    env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde)
    env.db.add(models.ScanJob(id=21, workspace_id=CLIENT, target="10.0.0.6", profile_id=5, status="done",
                              scan_type="external"))
    env.db.commit()
    env.connecte(ADMIN_CLIENT)

    liste = {j["id"]: (j["runs_on"], j["probe_name"]) for j in env.https.get("/scan/jobs").json()}
    detail = env.https.get("/scan/jobs/20").json()["job"]

    assert liste == {20: ("probe", "site-paris"), 21: ("platform", None)}
    assert (detail["runs_on"], detail["probe_name"]) == ("probe", "site-paris")


# ── Découverte d'hôtes sur la sonde ───────────────────────────────────────────

AVEC_DECOUVERTE = {"wait": 0, "kinds": "scan,discovery"}


def _decouverte_en_attente(env, workspace_id=CLIENT, network_range="10.1.2.0/24"):
    job = models.DiscoveryJob(workspace_id=workspace_id, network_range=network_range, status="queued",
                              total=254, hosts_json="[]")
    env.db.add(job)
    env.db.commit()
    return job.id


def test_une_decouverte_part_sur_la_sonde_et_en_revient(env):
    probe_id, sonde = env.sonde_enrolee()
    decouverte = _decouverte_en_attente(env)

    prise = env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde)
    progression = env.https.post(f"/probe/v1/discoveries/{decouverte}/progress", headers=sonde,
                                 json={"probed": 128, "hosts": [{"ip": "10.1.2.7", "hostname": "nas.lan"}]})
    env.db.expire_all()
    en_cours = env.db.get(models.DiscoveryJob, decouverte)
    vu_en_cours = (en_cours.status, en_cours.probe_id, en_cours.probed, json.loads(en_cours.hosts_json))
    rapport = env.https.post(f"/probe/v1/discoveries/{decouverte}/report", headers=sonde, json={
        "discovery_id": decouverte, "status": "done", "probed": 254,
        "hosts": [{"ip": "10.1.2.40", "hostname": None}, {"ip": "10.1.2.7", "hostname": "nas.lan"}],
    })
    renvoi = env.https.post(f"/probe/v1/discoveries/{decouverte}/report", headers=sonde,
                            json={"discovery_id": decouverte, "status": "done", "probed": 254, "hosts": []})

    assert prise.status_code == 200
    assert prise.headers["Cache-Control"] == "no-store"
    assert prise.json() == {"kind": "discovery", "discovery_id": decouverte, "workspace_id": CLIENT,
                            "network_range": "10.1.2.0/24", "allowlist": "10.0.0.0/8", "budget_seconds": 3600}
    assert progression.json() == {"cancel": False}
    assert vu_en_cours == ("running", probe_id, 128, [{"ip": "10.1.2.7", "hostname": "nas.lan"}])
    assert rapport.status_code == 200
    env.db.expire_all()
    fini = env.db.get(models.DiscoveryJob, decouverte)
    assert (fini.status, fini.probed, fini.error) == ("done", 254, None)
    assert [h["ip"] for h in json.loads(fini.hosts_json)] == ["10.1.2.7", "10.1.2.40"], "triés par adresse"
    assert renvoi.status_code == 404, "un rapport n'est accepté qu'une fois"
    assert [e["kind"] for e in env.https.get(f"/probes/{probe_id}/events").json()][:2] == ["report_received", "job_claimed"]


def test_une_sonde_d_avant_la_decouverte_ne_la_recoit_pas(env):
    _, sonde = env.sonde_enrolee()
    _decouverte_en_attente(env)

    reponse = env.https.get("/probe/v1/jobs/next", params={"wait": 0}, headers=sonde)

    assert reponse.status_code == 204


def test_la_decouverte_passe_avant_les_scans_en_attente(env):
    _, sonde = env.sonde_enrolee()
    env.https.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]})
    env.job_soumis(20)
    decouverte = _decouverte_en_attente(env)

    premier = env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde).json()
    second = env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde).json()

    assert (premier.get("discovery_id"), second.get("job_id")) == (decouverte, 20)


def test_une_annulation_de_decouverte_est_transmise_a_la_sonde(env):
    _, sonde = env.sonde_enrolee()
    decouverte = _decouverte_en_attente(env)
    env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde)
    env.db.get(models.DiscoveryJob, decouverte).cancel_requested = True
    env.db.commit()

    reponse = env.https.post(f"/probe/v1/discoveries/{decouverte}/progress", json={"probed": 10, "hosts": []},
                             headers=sonde)

    assert reponse.json() == {"cancel": True}


@pytest.mark.parametrize("hotes", [
    [{"ip": "10.9.9.9", "hostname": None}],      # hors de la plage découverte
    [{"ip": "pas-une-ip", "hostname": None}],
    "pas une liste",
])
def test_des_hotes_incoherents_sont_refuses(env, hotes):
    _, sonde = env.sonde_enrolee()
    decouverte = _decouverte_en_attente(env)
    env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde)

    reponse = env.https.post(f"/probe/v1/discoveries/{decouverte}/progress", json={"probed": 1, "hosts": hotes},
                             headers=sonde)

    assert reponse.status_code == 422


def test_une_sonde_ne_voit_pas_les_decouvertes_d_un_autre_client(env):
    _, sonde = env.sonde_enrolee(CLIENT)
    decouverte = _decouverte_en_attente(env, VOISIN)

    prise = env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde)
    progression = env.https.post(f"/probe/v1/discoveries/{decouverte}/progress", json={"probed": 1, "hosts": []},
                                 headers=sonde)

    assert (prise.status_code, progression.status_code) == (204, 404)


def test_revoquer_une_sonde_clot_sa_decouverte_en_cours(env):
    probe_id, sonde = env.sonde_enrolee()
    decouverte = _decouverte_en_attente(env)
    env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde)

    env.https.post(f"/probes/{probe_id}/revoke")

    env.db.expire_all()
    job = env.db.get(models.DiscoveryJob, decouverte)
    assert job.status == "failed" and "revoked" in job.error


def test_supprimer_une_sonde_garde_ses_decouvertes(env):
    probe_id, sonde = env.sonde_enrolee()
    decouverte = _decouverte_en_attente(env)
    env.https.get("/probe/v1/jobs/next", params=AVEC_DECOUVERTE, headers=sonde)

    assert env.https.delete(f"/probes/{probe_id}").status_code == 200

    env.db.expire_all()
    job = env.db.get(models.DiscoveryJob, decouverte)
    assert (job.status, job.probe_id) == ("failed", None)
