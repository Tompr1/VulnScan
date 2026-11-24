"""
Le journal d'audit dit, pour chaque action, qui l'a faite, sur quel client et
avec quel résultat : un refus sur le client d'un autre se voit.
"""
import pytest
from fastapi.testclient import TestClient

from app import main
from app.api.deps import get_db
from app.core import rate_limit
from app.core.audit import audit_entry
from app.core.auth import sign_jwt
from app.core.config import settings
from app.db import models

pytestmark = pytest.mark.integration

TECH = 7


def bearer(**claims):
    return f"Bearer {sign_jwt(claims)}"


# ── Ce qui est retenu d'une requête ──────────────────────────────────────────

def test_l_entree_nomme_le_compte_le_client_et_le_resultat():
    entree = audit_entry("POST", "/scan/jobs", bearer(uid=TECH, ws=3, sub="tech@msp.example"), 201, "198.51.100.4", "curl")

    assert entree == {
        "workspace_id": 3, "user_id": TECH, "actor_email": "tech@msp.example",
        "action": "POST /scan/jobs", "resource": "", "status_code": 201,
        "ip": "198.51.100.4", "user_agent": "curl",
    }


def test_une_session_sans_client_ouvert_est_journalisee_hors_client():
    entree = audit_entry("PUT", "/settings/dataset-refresh", bearer(uid=1, sub="admin@msp.example"), 200, "", "")

    assert (entree["workspace_id"], entree["user_id"]) == (None, 1)


@pytest.mark.parametrize(
    "authorization",
    [
        "",
        "Basic dXNlcjpwYXNz",
        "Bearer pas-un-jeton",
        bearer(uid=TECH, ws=3, sub="tech@msp.example")[:-4] + "AAAA",  # signature falsifiée
    ],
    ids=["sans jeton", "autre schéma", "jeton illisible", "signature falsifiée"],
)
def test_un_jeton_non_verifie_ne_designe_ni_auteur_ni_client(authorization):
    entree = audit_entry("POST", "/auth/login", authorization, 401, "198.51.100.4", "")

    assert (entree["workspace_id"], entree["user_id"], entree["actor_email"]) == (None, None, "")
    assert entree["status_code"] == 401


def test_un_jeton_expire_ne_designe_personne(monkeypatch):
    jeton = sign_jwt({"uid": TECH, "ws": 3, "sub": "tech@msp.example"}, ttl_seconds=-1)

    entree = audit_entry("DELETE", "/assets/4", f"Bearer {jeton}", 401, "", "")

    assert entree["user_id"] is None


# ── Le journal de l'application ──────────────────────────────────────────────

@pytest.fixture
def application(session_factory, db, monkeypatch):
    db.add_all([models.Workspace(id=1, name="client"), models.Workspace(id=2, name="voisin")])
    db.add(models.User(id=TECH, email="tech@msp.example", password_hash="x"))
    db.flush()
    db.add(models.AccessGrant(user_id=TECH, workspace_id=1, role="analyst"))
    db.commit()
    monkeypatch.setattr(main, "SessionLocal", session_factory)
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:1/0")  # rate limit ouvert
    monkeypatch.setattr(rate_limit, "_client", None)

    def test_db():
        with session_factory() as s:
            yield s

    main.app.dependency_overrides[get_db] = test_db
    yield TestClient(main.app)  # sans « with » : pas de démarrage (migrations, planificateur)
    main.app.dependency_overrides.pop(get_db, None)


def journal(db):
    db.expire_all()
    return [
        (e.action, e.workspace_id, e.user_id, e.actor_email, e.status_code)
        for e in db.query(models.AuditLog).order_by(models.AuditLog.id)
    ]


def test_une_tentative_d_ouvrir_le_client_d_un_autre_est_journalisee(application, db):
    jeton = bearer(uid=TECH, ws=1, sub="tech@msp.example")

    application.post("/auth/select-client/2", headers={"Authorization": jeton})

    assert journal(db) == [("POST /auth/select-client/2", 1, TECH, "tech@msp.example", 404)]


def test_un_echec_de_connexion_est_journalise_sans_auteur(application, db):
    application.post("/auth/login", json={"email": "tech@msp.example", "password": "faux"})

    assert journal(db) == [("POST /auth/login", None, None, "", 401)]


def test_les_lectures_ne_sont_pas_journalisees(application, db):
    application.get("/auth/clients", headers={"Authorization": bearer(uid=TECH, ws=1, sub="tech@msp.example")})

    assert journal(db) == []
