"""
Un scan réseau interne part uniquement de la sonde du client : depuis la
plateforme, il atteindrait le réseau de la plateforme, pas celui du client.
Sans sonde en ligne il est refusé, et sa cible doit être dans les réseaux
autorisés du client.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_probes, routes_scan
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.job_queue import ProbeAwareJobQueue, get_job_queue
from app.core.workspace_settings import client_allowlist, set_client_allowlist
from app.db import models
from tests.fakes import SpyJobQueue

pytestmark = pytest.mark.integration

ROOT, ANALYSTE = 1, 2


@pytest.fixture
def file():
    return SpyJobQueue()


@pytest.fixture
def api(session_factory, db, workspace, file):
    db.add_all([
        models.User(id=ROOT, email="root@msp.example", password_hash="x", is_global_admin=True),
        models.User(id=ANALYSTE, email="analyste@client.example", password_hash="x"),
    ])
    db.flush()
    db.add(models.AccessGrant(user_id=ANALYSTE, workspace_id=1, role="analyst"))
    db.commit()
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_scan.router)
    app.include_router(routes_probes.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[get_job_queue] = lambda: ProbeAwareJobQueue(session_factory, file)
    app.dependency_overrides[require_auth] = lambda: {"uid": ANALYSTE, "ws": 1, "sub": "analyste@client.example"}
    return TestClient(app, base_url="https://platform.example")


def scan(api, target="192.168.3.10", scan_type="internal"):
    return api.post("/scan/jobs", json={"target": target, "profile_id": 5, "scan_type": scan_type})


def test_sans_sonde_un_scan_reseau_est_refuse_et_rien_n_est_lance(api, db, file):
    reponse = scan(api)

    assert reponse.status_code == 409
    assert "no scan probe" in reponse.json()["detail"]
    assert file.scans == []
    assert db.query(models.ScanJob).count() == 0


def test_une_sonde_hors_ligne_ne_permet_pas_de_lancer_un_scan_reseau(api, file, sonde_en_ligne):
    sonde_en_ligne(1, last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=10))

    reponse = scan(api)

    assert reponse.status_code == 409
    assert "offline" in reponse.json()["detail"]
    assert file.scans == []


def test_une_sonde_en_attente_d_enrolement_ne_compte_pas(api, db):
    db.add(models.Probe(workspace_id=1, name="a-installer", status="pending"))
    db.commit()

    assert scan(api).status_code == 409


def test_la_sonde_d_un_autre_client_ne_compte_pas(api, sonde_en_ligne):
    sonde_en_ligne(2)

    assert scan(api).status_code == 409


@pytest.mark.parametrize("cible", ["192.168.2.0/24", "192.168.2.10", "192.168.3.0/23", "192.168.3.10,192.168.2.10"])
def test_une_cible_hors_des_reseaux_autorises_est_refusee(api, db, file, sonde_en_ligne, cible):
    sonde_en_ligne(1)
    set_client_allowlist(db, 1, ["192.168.3.0/24"])

    reponse = scan(api, cible)

    assert reponse.status_code == 409
    assert "outside this client's allowed networks (192.168.3.0/24)" in reponse.json()["detail"]
    assert file.scans == []


@pytest.mark.parametrize("cible", ["192.168.3.10", "192.168.3.0/24", "192.168.3.128/25"])
def test_une_cible_dans_les_reseaux_autorises_part_sur_la_sonde(api, db, file, sonde_en_ligne, cible):
    sonde_en_ligne(1)
    set_client_allowlist(db, 1, ["192.168.3.0/24"])

    reponse = scan(api, cible)

    assert reponse.status_code == 200, reponse.text
    db.expire_all()
    job = db.get(models.ScanJob, reponse.json()["id"])
    assert (job.status, job.runs_on, file.scans) == ("queued", "probe", [])


def test_un_scan_externe_sans_sonde_part_de_la_plateforme(api, file):
    reponse = scan(api, "https://www.example.com", scan_type="external")

    assert reponse.status_code == 200, reponse.text
    assert file.scans == [reponse.json()["id"]]


def test_la_planification_d_un_scan_reseau_sans_sonde_est_refusee(api, db):
    reponse = api.post("/scan/schedules", json={"target": "192.168.3.10", "profile_id": 5, "scan_type": "internal"})

    assert reponse.status_code == 409
    assert db.query(models.ScanSchedule).count() == 0


def test_relancer_un_scan_reseau_sans_sonde_est_refuse(api, db, file):
    db.add(models.ScanJob(id=40, workspace_id=1, target="192.168.3.10", profile_id=5, status="done", scan_type="internal"))
    db.commit()

    reponse = api.post("/scan/jobs/40/rescan")

    assert reponse.status_code == 409
    assert file.scans == []


def test_le_client_voit_si_il_peut_lancer_un_scan_reseau(api, db, sonde_en_ligne):
    set_client_allowlist(db, 1, ["192.168.3.0/24"])
    sans_sonde = api.get("/scan/network-availability").json()
    sonde_en_ligne(1)
    avec_sonde = api.get("/scan/network-availability").json()

    assert (sans_sonde["available"], sans_sonde["reason"]) == (False, "no_probe")
    assert avec_sonde == {"available": True, "reason": None, "message": None, "allowlist": "192.168.3.0/24"}


# ── Réseaux autorisés, réglés par Root ────────────────────────────────────────

def test_root_regle_les_reseaux_autorises_d_un_client(api, db):
    api.app.dependency_overrides[require_auth] = lambda: {"uid": ROOT, "ws": 1, "sub": "root@msp.example"}

    reponse = api.put("/probes/clients/1/allowlist", json={"allowlist": "192.168.3.0/24, .corp.local"})
    vue = {c["id"]: c for c in api.get("/probes").json()["clients"]}

    assert reponse.status_code == 200, reponse.text
    assert client_allowlist(db, 1) == ["192.168.3.0/24", ".corp.local"]
    assert vue[1]["allowlist"] == ["192.168.3.0/24", ".corp.local"]
    assert vue[2]["allowlist"] is None, "l'autre client garde le défaut de la plateforme"


def test_vider_les_reseaux_autorises_revient_au_defaut_de_la_plateforme(api, db):
    api.app.dependency_overrides[require_auth] = lambda: {"uid": ROOT, "ws": 1, "sub": "root@msp.example"}
    set_client_allowlist(db, 1, ["192.168.3.0/24"])

    api.put("/probes/clients/1/allowlist", json={"allowlist": ""})

    assert client_allowlist(db, 1) is None


@pytest.mark.parametrize("saisie", ["192.168.3.0/33", "pas un réseau", "*,10.0.0.0/8"])
def test_des_reseaux_illisibles_sont_refuses(api, db, saisie):
    api.app.dependency_overrides[require_auth] = lambda: {"uid": ROOT, "ws": 1, "sub": "root@msp.example"}

    reponse = api.put("/probes/clients/1/allowlist", json={"allowlist": saisie})

    assert reponse.status_code == 422
    assert client_allowlist(db, 1) is None


def test_un_admin_de_client_ne_regle_pas_les_reseaux_autorises(api):
    assert api.put("/probes/clients/1/allowlist", json={"allowlist": "*"}).status_code == 403
