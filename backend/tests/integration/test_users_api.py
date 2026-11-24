"""
Connexion et gestion des comptes avec le modèle d'accès MSP : un compte
n'appartient à aucun client, il en atteint par ses droits.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.access.domain import Role
from app.access.repository import SqlAccessRepository
from app.api import routes_auth, routes_settings
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core import rate_limit
from app.core.auth import require_auth, verify_jwt
from app.core.config import settings
from app.core.password import hash_password, verify_password
from app.db import models

pytestmark = pytest.mark.integration

MOT_DE_PASSE = "Correct-Horse-42"
CLIENT = 2


@pytest.fixture
def comptes(db):
    """Clients 1 à 3 ; un compte par situation."""
    db.add_all([models.Workspace(id=i, name=f"client-{i}") for i in (1, 2, 3)])
    secret = hash_password(MOT_DE_PASSE)
    db.add_all([
        models.User(id=1, email="admin@msp.example", password_hash=secret, is_global_admin=True),
        models.User(id=2, email="tech@client2.example", password_hash=secret),
        models.User(id=3, email="tech@msp.example", password_hash=secret),
        models.User(id=4, email="tech@client1.example", password_hash=secret),
        models.User(id=5, email="sans-acces@msp.example", password_hash=secret),
        models.User(id=9, email="admin-client2@client2.example", password_hash=secret),
    ])
    db.add_all([
        models.AccessGrant(user_id=2, workspace_id=2, role="viewer"),
        models.AccessGrant(user_id=3, workspace_id=2, role="analyst"),
        models.AccessGrant(user_id=3, workspace_id=3, role="admin"),
        models.AccessGrant(user_id=4, workspace_id=1, role="admin"),
        models.AccessGrant(user_id=9, workspace_id=2, role="admin"),
    ])
    db.commit()


@pytest.fixture
def client(session_factory, comptes, monkeypatch):
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:1/0")  # rate limit ouvert
    monkeypatch.setattr(rate_limit, "_client", None)
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_auth.router)
    app.include_router(routes_settings.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides.update({
        get_db: test_db,
        require_auth: lambda: {"ws": CLIENT, "uid": 9, "sub": "admin-client2@client2.example", "role": "admin"},
    })
    return TestClient(app)


def connexion(client, email):
    return client.post("/auth/login", json={"email": email, "password": MOT_DE_PASSE})


# ── Connexion ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("email", "client_ouvert", "role"),
    [
        ("admin@msp.example", 1, "admin"),
        ("tech@client2.example", 2, "viewer"),
        ("tech@msp.example", 2, "analyst"),
    ],
    ids=["admin global", "un seul client", "plusieurs clients"],
)
def test_la_connexion_ouvre_le_premier_client_accessible_avec_le_role_qu_on_y_a(client, email, client_ouvert, role):
    reponse = connexion(client, email)

    assert reponse.status_code == 200, reponse.text
    jeton = verify_jwt(reponse.json()["token"])
    assert (jeton["ws"], jeton["role"]) == (client_ouvert, role)
    assert (reponse.json()["workspace_id"], reponse.json()["role"]) == (client_ouvert, role)


def test_un_compte_sans_aucun_client_ne_peut_pas_se_connecter(client):
    reponse = connexion(client, "sans-acces@msp.example")

    assert reponse.status_code == 403


def test_un_mauvais_mot_de_passe_est_refuse(client):
    reponse = client.post("/auth/login", json={"email": "admin@msp.example", "password": "faux"})

    assert reponse.status_code == 401


# ── Comptes vus depuis le client 2 ───────────────────────────────────────────

def test_la_liste_montre_les_comptes_qui_ouvrent_ce_client_et_lesquels_son_admin_peut_gerer(client):
    reponse = client.get("/settings/users")

    assert reponse.status_code == 200
    assert [(u["email"], u["role"], u["is_global_admin"], u["other_clients"], u["manageable"]) for u in reponse.json()] == [
        ("admin-client2@client2.example", "admin", False, 0, True),
        ("admin@msp.example", "admin", True, 2, False),
        ("tech@client2.example", "viewer", False, 0, True),
        ("tech@msp.example", "analyst", False, 1, False),
    ]


def test_un_compte_cree_par_l_admin_d_un_client_n_ouvre_que_ce_client(client, db):
    reponse = client.post("/settings/users", json={"email": "nouveau@client2.example", "password": MOT_DE_PASSE, "role": "analyst"})

    assert reponse.status_code == 200, reponse.text
    cree = db.query(models.User).filter_by(email="nouveau@client2.example").one()
    assert SqlAccessRepository(db).access_of(cree).roles == {CLIENT: Role.ANALYST}
    assert not cree.is_global_admin


def test_on_ne_peut_pas_creer_un_compte_dont_l_email_existe_deja_chez_un_autre_client(client):
    reponse = client.post("/settings/users", json={"email": "tech@client1.example", "password": MOT_DE_PASSE})

    assert reponse.status_code == 409


def test_l_admin_d_un_client_reinitialise_le_mot_de_passe_d_un_compte_de_ce_seul_client(client, db):
    reponse = client.put("/settings/users/2/password", json={"new_password": "Nouveau-Secret-1"})

    assert reponse.status_code == 200, reponse.text
    db.expire_all()
    assert verify_password("Nouveau-Secret-1", db.get(models.User, 2).password_hash)


@pytest.mark.parametrize(
    ("methode", "chemin", "corps"),
    [("PUT", "/settings/users/{id}/password", {"new_password": "Pirate-123456!"}), ("DELETE", "/settings/users/{id}", None)],
    ids=["mot de passe", "suppression"],
)
@pytest.mark.parametrize(
    ("user_id", "statut"),
    [(3, 403), (1, 403), (4, 404), (5, 404), (99, 404)],
    ids=["ouvre aussi un autre client", "admin global", "compte d'un autre client", "compte sans client", "inconnu"],
)
def test_l_admin_d_un_client_ne_touche_pas_un_compte_qui_depasse_son_client(client, db, methode, chemin, corps, user_id, statut):
    avant = {u.id: u.password_hash for u in db.query(models.User)}

    reponse = client.request(methode, chemin.format(id=user_id), json=corps)

    assert reponse.status_code == statut
    db.expire_all()
    assert {u.id: u.password_hash for u in db.query(models.User)} == avant


def test_l_admin_d_un_client_supprime_un_compte_de_ce_seul_client(client, db):
    reponse = client.delete("/settings/users/2")

    assert reponse.status_code == 200
    db.expire_all()
    assert db.get(models.User, 2) is None


def test_chacun_change_son_propre_mot_de_passe_quel_que_soit_le_client_ouvert(client, db):
    client.app.dependency_overrides[require_auth] = lambda: {"ws": CLIENT, "uid": 3, "sub": "tech@msp.example", "role": "analyst"}

    reponse = client.put(
        "/settings/users/me/password", json={"current_password": MOT_DE_PASSE, "new_password": "Nouveau-Secret-1"}
    )

    assert reponse.status_code == 200, reponse.text
    db.expire_all()
    assert verify_password("Nouveau-Secret-1", db.get(models.User, 3).password_hash)
