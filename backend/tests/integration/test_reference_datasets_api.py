"""
Le référentiel (NVD, CISA KEV, EPSS…) est commun à tous les clients : chacun
le lit, seul un admin global le modifie ou le rafraîchit.
"""
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_datasets, routes_settings, routes_threat_intel
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.platform_settings import DATASET_REFRESH_KEY, get_platform_setting
from app.cve.reference_datasets import enabled_dataset_paths, latest_dataset_path
from app.db import models
from app.threat_intel import aggregator

pytestmark = pytest.mark.integration

ADMIN_GLOBAL, ADMIN_CLIENT, LECTEUR = 1, 2, 3


def session(uid, ws):
    """Claims d'un jeton ; le rôle est relu en base à chaque requête."""
    return {"uid": uid, "ws": ws, "sub": f"user{uid}@msp.example"}


@pytest.fixture
def referentiel(db, tmp_path):
    db.add_all([models.Workspace(id=1, name="client-1"), models.Workspace(id=2, name="client-2")])
    db.add_all([
        models.User(id=ADMIN_GLOBAL, email="admin@msp.example", password_hash="x", is_global_admin=True),
        models.User(id=ADMIN_CLIENT, email="admin@client1.example", password_hash="x"),
        models.User(id=LECTEUR, email="lecteur@msp.example", password_hash="x"),
    ])
    db.flush()
    db.add_all([
        models.AccessGrant(user_id=ADMIN_CLIENT, workspace_id=1, role="admin"),
        models.AccessGrant(user_id=LECTEUR, workspace_id=1, role="viewer"),
        models.AccessGrant(user_id=LECTEUR, workspace_id=2, role="viewer"),
    ])
    kev = tmp_path / "cisa_kev.json"
    kev.write_text(json.dumps([{"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Tool"}]))
    db.add(models.CveDataset(id=10, name="CISA KEV", kind="cisa_kev", path=str(kev), enabled=True))
    db.commit()


@pytest.fixture
def client(session_factory, referentiel):
    aggregator.invalidate()
    app = FastAPI()
    install_validation_error_handler(app)
    for module in (routes_datasets, routes_settings, routes_threat_intel):
        app.include_router(module.router)

    def test_db():
        with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[require_auth] = lambda: session(ADMIN_CLIENT, 1)
    yield TestClient(app)
    aggregator.invalidate()


def connecte(client, claims):
    client.app.dependency_overrides[require_auth] = lambda: claims


# ── Lecture : la même chose depuis chaque client ─────────────────────────────

@pytest.mark.parametrize("chemin", ["/datasets", "/datasets/browse/cisa_kev", "/threat-intel/stats", "/threat-intel/cves"])
def test_chaque_client_lit_le_meme_referentiel(client, chemin):
    connecte(client, session(LECTEUR, 1))
    vu_par_le_client_1 = client.get(chemin)
    connecte(client, session(LECTEUR, 2))
    vu_par_le_client_2 = client.get(chemin)

    assert vu_par_le_client_1.status_code == 200, vu_par_le_client_1.text
    assert vu_par_le_client_1.json() == vu_par_le_client_2.json()


def test_le_threat_intel_s_appuie_sur_le_referentiel_commun(client):
    reponse = client.get("/threat-intel/cves/CVE-2024-0001")

    assert reponse.status_code == 200
    assert reponse.json()["kev"] is True


def _ecrire_kev(tmp_path, *cves):
    (tmp_path / "cisa_kev.json").write_text(json.dumps([{"cveID": cve} for cve in cves]))


def test_le_cache_threat_intel_est_unique_pour_tous_les_clients_jusqu_a_son_invalidation(client, tmp_path):
    client.get("/threat-intel/stats")
    _ecrire_kev(tmp_path, "CVE-2024-0001", "CVE-2024-0002")

    connecte(client, session(LECTEUR, 2))
    encore_en_cache = client.get("/threat-intel/stats").json()["total_cves"]
    connecte(client, session(ADMIN_CLIENT, 1))
    client.post("/threat-intel/refresh")
    apres_invalidation = client.get("/threat-intel/stats").json()["total_cves"]

    assert (encore_en_cache, apres_invalidation) == (1, 2)


def test_le_cache_threat_intel_expire_de_lui_meme(client, tmp_path, monkeypatch):
    client.get("/threat-intel/stats")
    _ecrire_kev(tmp_path, "CVE-2024-0001", "CVE-2024-0002")
    monkeypatch.setattr(aggregator, "_CACHE_TTL_SECONDS", 0.0)

    assert client.get("/threat-intel/stats").json()["total_cves"] == 2


# ── Écriture : admin global seulement ────────────────────────────────────────

ECRITURES = [
    ("POST", "/datasets", {"json": {"name": "x", "kind": "epss", "path": "/tmp/x.json"}}),
    ("POST", "/datasets/upload", {"params": {"kind": "epss"}, "files": {"file": ("x.json", b"[]")}}),
    ("PATCH", "/datasets/10", {"json": {"enabled": False}}),
    ("PATCH", "/datasets/10/toggle", {}),
    ("DELETE", "/datasets/10", {}),
    ("POST", "/datasets/refresh", {"json": {}}),
    ("POST", "/datasets/refresh/cancel", {}),
    ("PUT", "/settings/dataset-refresh", {"json": {"enabled": True}}),
]


@pytest.mark.parametrize(("methode", "chemin", "options"), ECRITURES, ids=[f"{m} {c}" for m, c, _ in ECRITURES])
@pytest.mark.parametrize(
    ("claims", "statut"),
    [(session(ADMIN_CLIENT, 1), 403), ({"ws": 1, "sub": "ancien-jeton@msp.example", "role": "admin"}, 401)],
    ids=["admin d'un client", "jeton sans uid"],
)
def test_seul_un_admin_global_modifie_le_referentiel(client, db, methode, chemin, options, claims, statut):
    connecte(client, claims)

    reponse = client.request(methode, chemin, **options)

    assert reponse.status_code == statut
    db.expire_all()
    assert [(d.id, d.enabled) for d in db.query(models.CveDataset)] == [(10, True)]
    assert db.query(models.PlatformSetting).count() == 0


def test_l_admin_global_active_ou_desactive_un_dataset_pour_tous_les_clients(client, db):
    connecte(client, session(ADMIN_GLOBAL, 2))

    reponse = client.patch("/datasets/10/toggle")

    assert reponse.status_code == 200 and reponse.json()["enabled"] is False
    db.expire_all()
    assert enabled_dataset_paths(db, "cisa_kev") == []


def test_la_modification_d_un_dataset_ne_touche_que_ses_champs_editables(client, db):
    connecte(client, session(ADMIN_GLOBAL, 1))

    reponse = client.patch("/datasets/10", json={"id": 99, "created_at": None, "name": "KEV du jour"})

    assert reponse.status_code == 200
    db.expire_all()
    assert [(d.id, d.name) for d in db.query(models.CveDataset)] == [(10, "KEV du jour")]


def test_un_dataset_cree_par_l_admin_global_est_visible_de_tous_les_clients(client, db):
    connecte(client, session(ADMIN_GLOBAL, 1))
    client.post("/datasets", json={"name": "EPSS", "kind": "epss", "path": "/data/cve/epss.json"})

    connecte(client, session(LECTEUR, 2))
    noms = [d["name"] for d in client.get("/datasets").json()]

    assert noms == ["CISA KEV", "EPSS"]


def test_le_rafraichissement_automatique_est_un_reglage_de_la_plateforme(client, db):
    connecte(client, session(ADMIN_GLOBAL, 1))
    client.put("/settings/dataset-refresh", json={"enabled": True, "interval_hours": 12})

    connecte(client, session(LECTEUR, 2))
    vu_par_un_autre_client = client.get("/settings/dataset-refresh").json()

    assert vu_par_un_autre_client == {"enabled": True, "interval_hours": 12}
    assert get_platform_setting(db, DATASET_REFRESH_KEY, {}) == {"enabled": True, "interval_hours": 12}


# ── Sélection des fichiers ───────────────────────────────────────────────────

def test_seuls_les_datasets_actifs_sont_lus_le_plus_recent_d_abord(db):
    db.add_all([
        models.CveDataset(id=1, name="v1", kind="epss", path="/v1.json", enabled=True),
        models.CveDataset(id=2, name="v2", kind="epss", path="/v2.json", enabled=False),
        models.CveDataset(id=3, name="v3", kind="epss", path="/v3.json", enabled=True),
        models.CveDataset(id=4, name="kev", kind="cisa_kev", path="/kev.json", enabled=True),
    ])
    db.commit()

    assert enabled_dataset_paths(db, "epss") == ["/v3.json", "/v1.json"]
    assert latest_dataset_path(db, "epss") == "/v3.json"
    assert latest_dataset_path(db, "osv") is None
