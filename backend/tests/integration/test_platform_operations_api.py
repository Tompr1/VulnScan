"""
L'infrastructure et la mise à jour de la plateforme sont l'affaire du MSP :
l'admin d'un client n'y a pas accès.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_settings
from app.api.deps import get_db
from app.core.auth import require_auth
from app.db import models

pytestmark = pytest.mark.integration

ADMIN_GLOBAL, ADMIN_CLIENT = 1, 2


@pytest.fixture
def client(session_factory, db):
    db.add(models.Workspace(id=1, name="client"))
    db.add_all([
        models.User(id=ADMIN_GLOBAL, email="admin@msp.example", password_hash="x", is_global_admin=True),
        models.User(id=ADMIN_CLIENT, email="admin@client.example", password_hash="x"),
    ])
    db.flush()
    db.add(models.AccessGrant(user_id=ADMIN_CLIENT, workspace_id=1, role="admin"))
    db.commit()
    app = FastAPI()
    app.include_router(routes_settings.router)

    def test_db():
        with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = test_db
    return TestClient(app)


def connecte(client, uid):
    client.app.dependency_overrides[require_auth] = lambda: {"uid": uid, "ws": 1, "sub": f"user{uid}@example"}


@pytest.mark.parametrize(("methode", "chemin"), [("GET", "/settings/info"), ("POST", "/settings/update/trigger")])
def test_l_admin_d_un_client_n_atteint_pas_les_operations_de_la_plateforme(client, methode, chemin, monkeypatch):
    ecrits = []
    monkeypatch.setattr("builtins.open", lambda *a, **k: ecrits.append(a) or pytest.fail("fichier écrit"))
    connecte(client, ADMIN_CLIENT)

    reponse = client.request(methode, chemin)

    assert reponse.status_code == 403
    assert ecrits == []


def test_l_admin_global_voit_l_infrastructure(client):
    connecte(client, ADMIN_GLOBAL)

    reponse = client.get("/settings/info")

    assert reponse.status_code == 200
    assert "database_url" in reponse.json()
