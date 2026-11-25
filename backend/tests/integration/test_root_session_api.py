"""
Root : le contexte de la plateforme, sans client ouvert, réservé aux admins
globaux. On y lit ce que tous les clients partagent (référentiel, Threat
Intel, version) et on administre clients et comptes ; aucune donnée d'un
client n'y est accessible.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_access, routes_auth, routes_datasets, routes_settings, routes_threat_intel
from app.api.deps import NO_CLIENT_SELECTED, get_db
from app.api.validation import install_validation_error_handler
from app.core import rate_limit
from app.core.auth import sign_jwt, verify_jwt
from app.core.config import settings
from app.core.password import hash_password
from app.db import models

pytestmark = pytest.mark.integration

MOT_DE_PASSE = "Correct-Horse-42"
ADMIN_GLOBAL, LECTEUR, SANS_CLIENT = 1, 2, 3

LECTURES_COMMUNES = ["/datasets", "/threat-intel/stats", "/settings/dataset-refresh"]


@pytest.fixture
def plateforme(db, tmp_path):
    db.add_all([models.Workspace(id=1, name="Acme"), models.Workspace(id=2, name="Globex")])
    secret = hash_password(MOT_DE_PASSE)
    db.add_all([
        models.User(id=ADMIN_GLOBAL, email="admin@msp.example", password_hash=secret, is_global_admin=True),
        models.User(id=LECTEUR, email="lecteur@acme.example", password_hash=secret),
        models.User(id=SANS_CLIENT, email="sans@msp.example", password_hash=secret),
    ])
    db.flush()
    db.add(models.AccessGrant(id=1, user_id=LECTEUR, workspace_id=1, role="viewer"))
    kev = tmp_path / "kev.json"
    kev.write_text('[{"cveID": "CVE-2024-0001"}]')
    db.add(models.CveDataset(id=1, name="CISA KEV", kind="cisa_kev", path=str(kev), enabled=True))
    db.add(models.Asset(id=1, workspace_id=1, name="srv-acme"))
    db.commit()


@pytest.fixture
def client(session_factory, plateforme, monkeypatch):
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:1/0")  # rate limit ouvert
    monkeypatch.setattr(rate_limit, "_client", None)
    app = FastAPI()
    install_validation_error_handler(app)
    for module in (routes_auth, routes_datasets, routes_threat_intel, routes_settings, routes_access):
        app.include_router(module.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = test_db
    return TestClient(app)


def connexion(client, email):
    reponse = client.post("/auth/login", json={"email": email, "password": MOT_DE_PASSE})
    assert reponse.status_code == 200, reponse.text
    return reponse.json()["token"]


def avec(jeton):
    return {"Authorization": f"Bearer {jeton}"}


def root(client):
    reponse = client.post("/auth/select-root", headers=avec(connexion(client, "admin@msp.example")))
    assert reponse.status_code == 200, reponse.text
    return reponse.json()


# ── Ouvrir Root ──────────────────────────────────────────────────────────────

def test_l_admin_global_ouvre_root_une_session_sans_client(client):
    session = root(client)

    assert (session["workspace_id"], session["role"], session["is_global_admin"]) == (None, None, True)
    assert [c["name"] for c in session["clients"]] == ["Acme", "Globex"]
    assert "ws" not in verify_jwt(session["token"])


def test_seul_un_admin_global_ouvre_root(client):
    reponse = client.post("/auth/select-root", headers=avec(connexion(client, "lecteur@acme.example")))

    assert reponse.status_code == 403


def test_depuis_root_on_ouvre_un_client(client):
    jeton = root(client)["token"]

    reponse = client.post("/auth/select-client/2", headers=avec(jeton))

    assert reponse.status_code == 200 and reponse.json()["workspace_id"] == 2


# ── Ce que Root lit ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("chemin", LECTURES_COMMUNES)
def test_root_lit_le_referentiel_commun(client, chemin):
    reponse = client.get(chemin, headers=avec(root(client)["token"]))

    assert reponse.status_code == 200, reponse.text


def test_root_administre_les_acces(client):
    reponse = client.get("/access/users", headers=avec(root(client)["token"]))

    assert reponse.status_code == 200


@pytest.mark.parametrize("chemin", ["/settings/stats", "/settings/allowlist", "/settings/users"])
def test_root_ne_voit_aucune_donnee_d_un_client(client, chemin):
    reponse = client.get(chemin, headers=avec(root(client)["token"]))

    assert reponse.status_code == 403 and reponse.json()["detail"] == NO_CLIENT_SELECTED


# ── Les autres comptes lisent le référentiel depuis leur client ──────────────

@pytest.mark.parametrize("chemin", LECTURES_COMMUNES)
def test_un_lecteur_lit_le_referentiel_depuis_son_client(client, chemin):
    assert client.get(chemin, headers=avec(connexion(client, "lecteur@acme.example"))).status_code == 200


@pytest.mark.parametrize("chemin", LECTURES_COMMUNES)
def test_sans_client_ouvert_un_compte_ordinaire_ne_lit_rien(client, chemin):
    jeton = sign_jwt({"uid": LECTEUR, "sub": "lecteur@acme.example"})  # ni client ni Root

    reponse = client.get(chemin, headers=avec(jeton))

    assert reponse.status_code == 403 and reponse.json()["detail"] == NO_CLIENT_SELECTED


@pytest.mark.parametrize("chemin", LECTURES_COMMUNES)
def test_un_droit_retire_ferme_aussi_le_referentiel(client, db, chemin):
    jeton = connexion(client, "lecteur@acme.example")
    db.query(models.AccessGrant).delete()
    db.commit()

    assert client.get(chemin, headers=avec(jeton)).status_code == 403
