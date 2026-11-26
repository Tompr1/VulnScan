"""
Les paramètres d'un client sont réservés à son admin : un analyste ou un
lecteur ne les lit ni ne les modifie. Restent ouverts à tous les rôles les
compteurs du tableau de bord et le changement de son propre mot de passe.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_settings
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.db import models

pytestmark = pytest.mark.integration

CLIENT = 1

PARAMETRES = [
    ("GET", "/settings/allowlist", None),
    ("PUT", "/settings/allowlist", {"allowlist": "10.0.0.0/8"}),
    ("GET", "/settings/sla", None),
    ("PUT", "/settings/sla", {"critical": 7}),
    ("POST", "/settings/sla/reset", None),
    ("GET", "/settings/notifications", None),
    ("PUT", "/settings/notifications", {}),
    ("POST", "/settings/notifications/reset", None),
    ("GET", "/settings/auto-ai", None),
    ("PUT", "/settings/auto-ai", {"enabled": False}),
    ("GET", "/settings/sla-alert", None),
    ("PUT", "/settings/sla-alert", {"enabled": False}),
    ("GET", "/settings/auto-report", None),
    ("PUT", "/settings/auto-report", {"enabled": False}),
    ("GET", "/settings/users", None),
]


@pytest.fixture
def client(session_factory, db):
    db.add(models.Workspace(id=CLIENT, name="Acme"))
    db.commit()
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_settings.router)

    def test_db():
        with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = test_db
    return TestClient(app)


def en_tant_que(client, session_de, role):
    session = session_de(CLIENT, role)
    client.app.dependency_overrides[require_auth] = lambda: session
    return client


@pytest.mark.parametrize("role", ["analyst", "viewer"])
@pytest.mark.parametrize(("methode", "chemin", "corps"), PARAMETRES)
def test_un_analyste_ou_un_lecteur_n_accede_a_aucun_parametre(client, session_de, role, methode, chemin, corps):
    reponse = en_tant_que(client, session_de, role).request(methode, chemin, json=corps)

    assert reponse.status_code == 403, reponse.text


@pytest.mark.parametrize(("methode", "chemin", "corps"), [p for p in PARAMETRES if p[0] == "GET"])
def test_l_admin_du_client_lit_ses_parametres(client, session_de, methode, chemin, corps):
    assert en_tant_que(client, session_de, "admin").request(methode, chemin).status_code == 200


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_tous_les_roles_gardent_les_compteurs_du_tableau_de_bord(client, session_de, role):
    assert en_tant_que(client, session_de, role).get("/settings/stats").status_code == 200
