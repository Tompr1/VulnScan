"""
Parcours de session de bout en bout, avec de vrais jetons : connexion,
choix du client, puis droits relus en base à chaque requête.
"""
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_auth, routes_settings
from app.api.deps import NO_CLIENT_SELECTED, get_db, require_role
from app.api.validation import install_validation_error_handler
from app.core import rate_limit
from app.core.auth import verify_jwt
from app.core.config import settings
from app.core.password import hash_password
from app.db import models

pytestmark = pytest.mark.integration

MOT_DE_PASSE = "Correct-Horse-42"
ADMIN_GLOBAL, TECH, ADMIN_CLIENT_2 = 1, 2, 3
HIER = datetime(2026, 11, 23, 18, 0, tzinfo=timezone.utc)


@pytest.fixture
def plateforme(db):
    """Clients « Beta » (1), « alpha » (2), « Gamma » (3) ; un technicien
    analyste chez alpha et admin chez Gamma."""
    db.add_all([models.Workspace(id=1, name="Beta"), models.Workspace(id=2, name="alpha"), models.Workspace(id=3, name="Gamma")])
    secret = hash_password(MOT_DE_PASSE)
    db.add_all([
        models.User(id=ADMIN_GLOBAL, email="admin@msp.example", password_hash=secret, is_global_admin=True),
        models.User(id=TECH, email="tech@msp.example", password_hash=secret),
        models.User(id=ADMIN_CLIENT_2, email="admin@alpha.example", password_hash=secret),
    ])
    db.flush()
    db.add_all([
        models.AccessGrant(id=1, user_id=TECH, workspace_id=2, role="analyst"),
        models.AccessGrant(id=2, user_id=TECH, workspace_id=3, role="admin"),
        models.AccessGrant(id=3, user_id=ADMIN_CLIENT_2, workspace_id=2, role="admin"),
    ])
    db.commit()


@pytest.fixture
def client(session_factory, plateforme, monkeypatch):
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:1/0")  # rate limit ouvert
    monkeypatch.setattr(rate_limit, "_client", None)
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_auth.router)
    app.include_router(routes_settings.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = test_db
    return TestClient(app)


def connexion(client, email):
    reponse = client.post("/auth/login", json={"email": email, "password": MOT_DE_PASSE})
    assert reponse.status_code == 200, reponse.text
    return reponse.json()


def avec(jeton):
    return {"Authorization": f"Bearer {jeton}"}


def choisir(client, jeton, client_id):
    return client.post(f"/auth/select-client/{client_id}", headers=avec(jeton))


# ── Connexion et choix du client ─────────────────────────────────────────────

def test_la_connexion_liste_les_clients_accessibles_et_ouvre_le_premier(client):
    session = connexion(client, "tech@msp.example")

    assert session["clients"] == [{"id": 2, "name": "alpha", "role": "analyst"}, {"id": 3, "name": "Gamma", "role": "admin"}]
    assert (session["workspace_id"], session["role"], session["is_global_admin"]) == (2, "analyst", False)
    assert verify_jwt(session["token"])["ws"] == 2


def test_choisir_un_autre_client_donne_un_jeton_avec_le_role_qu_on_y_a(client):
    session = connexion(client, "tech@msp.example")

    reponse = choisir(client, session["token"], 3)

    assert reponse.status_code == 200
    jeton = verify_jwt(reponse.json()["token"])
    assert (jeton["ws"], jeton["role"], jeton["uid"]) == (3, "admin", TECH)
    assert client.get("/settings/users", headers=avec(reponse.json()["token"])).status_code == 200


@pytest.mark.parametrize("client_id", [1, 99], ids=["client sans droit", "client inexistant"])
def test_on_ne_peut_pas_choisir_un_client_auquel_on_n_a_pas_acces(client, client_id):
    session = connexion(client, "tech@msp.example")

    assert choisir(client, session["token"], client_id).status_code == 404


def test_un_admin_global_sans_aucun_client_se_connecte_sans_client_ouvert(client, db):
    db.query(models.Workspace).delete()
    db.commit()

    session = connexion(client, "admin@msp.example")
    reponse = client.get("/settings/stats", headers=avec(session["token"]))

    assert (session["workspace_id"], session["clients"]) == (None, [])
    assert "ws" not in verify_jwt(session["token"])
    assert reponse.status_code == 403 and reponse.json()["detail"] == NO_CLIENT_SELECTED


def test_l_admin_global_peut_ouvrir_n_importe_quel_client(client):
    session = connexion(client, "admin@msp.example")

    reponse = choisir(client, session["token"], 3)

    assert reponse.status_code == 200 and reponse.json()["role"] == "admin"


# ── Droits relus en base à chaque requête ────────────────────────────────────

def test_un_droit_retire_ferme_l_acces_sans_attendre_l_expiration_du_jeton(client, db):
    jeton = connexion(client, "admin@alpha.example")["token"]
    assert client.get("/settings/users", headers=avec(jeton)).status_code == 200

    db.query(models.AccessGrant).filter_by(id=3).delete()
    db.commit()

    reponse = client.get("/settings/stats", headers=avec(jeton))
    assert reponse.status_code == 403 and reponse.json()["detail"] == "No access to this client"


def test_un_role_abaisse_s_applique_meme_si_le_jeton_dit_admin(client, db):
    jeton = connexion(client, "admin@alpha.example")["token"]

    db.get(models.AccessGrant, 3).role = "viewer"
    db.commit()

    assert verify_jwt(jeton)["role"] == "admin"
    assert client.get("/settings/users", headers=avec(jeton)).status_code == 403
    assert client.get("/settings/stats", headers=avec(jeton)).status_code == 200


def test_le_role_transmis_aux_routes_est_celui_de_la_base_pas_celui_du_jeton(plateforme, db):
    verifier = require_role("viewer", "analyst", "admin")
    jeton_perime = {"uid": TECH, "ws": 2, "sub": "tech@msp.example", "role": "admin"}

    claims = verifier(claims=jeton_perime, user=db.get(models.User, TECH), db=db)

    assert claims["role"] == "analyst"


def test_un_compte_supprime_n_a_plus_de_session(client, db):
    jeton = connexion(client, "admin@alpha.example")["token"]

    db.delete(db.get(models.User, ADMIN_CLIENT_2))
    db.commit()

    assert client.get("/settings/stats", headers=avec(jeton)).status_code == 401
    assert client.get("/auth/clients", headers=avec(jeton)).status_code == 401


def test_sans_jeton_rien_n_est_accessible(client):
    assert client.get("/auth/clients").status_code == 401
    assert client.post("/auth/select-client/2").status_code == 401


# ── Écran de choix du client ─────────────────────────────────────────────────

def _finding(id, ws, severity, status="open", is_kev=False):
    return models.Finding(id=id, workspace_id=ws, job_id=ws * 10, target="t", plugin_id="p", title="f",
                          severity=severity, status=status, is_kev=is_kev, fingerprint=f"fp{id}")


def test_le_choix_du_client_montre_les_indicateurs_de_chaque_client_accessible(client, db):
    db.add_all([
        models.ScanJob(id=20, workspace_id=2, target="t", status="done", finished_at=HIER),
        models.ScanJob(id=21, workspace_id=2, target="t", status="failed", finished_at=datetime(2026, 11, 24, tzinfo=timezone.utc)),
        models.ScanJob(id=10, workspace_id=1, target="t", status="done", finished_at=HIER),
    ])
    db.add_all([
        _finding(1, 2, "critical", is_kev=True),
        _finding(2, 2, "critical"),
        _finding(3, 2, "high"),
        _finding(4, 2, "critical", status="closed", is_kev=True),
        _finding(5, 2, "medium", is_kev=True),
        _finding(6, 1, "critical", is_kev=True),
    ])
    db.commit()
    jeton = connexion(client, "tech@msp.example")["token"]

    reponse = client.get("/auth/clients", headers=avec(jeton))

    assert reponse.status_code == 200
    alpha, gamma = reponse.json()
    assert alpha.pop("last_scan_at").startswith("2026-11-23T18:00:00")  # avec ou sans fuseau selon la base
    assert alpha == {
        "id": 2, "name": "alpha", "role": "analyst",
        "open_findings": {"critical": 2, "high": 1}, "open_kev": 2,
    }
    assert gamma == {
        "id": 3, "name": "Gamma", "role": "admin",
        "open_findings": {"critical": 0, "high": 0}, "open_kev": 0, "last_scan_at": None,
    }


def test_l_admin_global_voit_tous_les_clients_dans_le_choix(client):
    jeton = connexion(client, "admin@msp.example")["token"]

    noms = [c["name"] for c in client.get("/auth/clients", headers=avec(jeton)).json()]

    assert noms == ["alpha", "Beta", "Gamma"]
