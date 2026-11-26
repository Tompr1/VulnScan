"""
Chaque client a sa propre allowlist de scan interne : ses plages et ses
domaines, lus par le worker au démarrage de chaque scan.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_settings
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.config import settings
from app.db import models
from app.scanner.client_allowlists import SqlClientAllowlists
from app.scanner.target import ScanTarget, ScanType

pytestmark = pytest.mark.integration

DEFAUT_PLATEFORME = "10.0.0.0/8"
CLIENT, VOISIN = 3, 4


@pytest.fixture
def clients(db, monkeypatch):
    monkeypatch.setattr(settings, "ALLOWLIST", DEFAUT_PLATEFORME)
    db.add_all([models.Workspace(id=CLIENT, name="client"), models.Workspace(id=VOISIN, name="voisin")])
    db.commit()


@pytest.fixture
def client(session_factory, clients, session_de):
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_settings.router)

    def test_db():
        with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[require_auth] = lambda: session_de(CLIENT, "admin", email="admin@client.example")
    return TestClient(app)


def autorise(session_factory, client_id, cible):
    policy = SqlClientAllowlists(session_factory, platform_default=settings.ALLOWLIST).policy_for(client_id)
    return policy.allows(ScanTarget.parse(cible), ScanType.INTERNAL)


# ── Lecture par le worker ────────────────────────────────────────────────────

def test_un_client_sans_allowlist_a_celle_par_defaut_de_la_plateforme(client, session_factory):
    assert autorise(session_factory, CLIENT, "10.1.2.3")
    assert not autorise(session_factory, CLIENT, "192.168.1.1")


def test_l_allowlist_d_un_client_s_applique_a_ses_scans_et_pas_a_ceux_du_voisin(client, session_factory):
    reponse = client.put("/settings/allowlist", json={"allowlist": "192.168.0.0/16, .client.example"})

    assert reponse.status_code == 200, reponse.text
    assert autorise(session_factory, CLIENT, "192.168.1.1")
    assert autorise(session_factory, CLIENT, "intranet.client.example")
    assert not autorise(session_factory, CLIENT, "10.1.2.3")  # remplace le défaut, ne s'y ajoute pas
    assert not autorise(session_factory, VOISIN, "192.168.1.1")
    assert autorise(session_factory, VOISIN, "10.1.2.3")


def test_le_changement_ne_touche_pas_le_reglage_du_processus(client):
    client.put("/settings/allowlist", json={"allowlist": "192.168.0.0/16"})

    assert settings.ALLOWLIST == DEFAUT_PLATEFORME


def test_une_allowlist_vide_revient_au_defaut_de_la_plateforme(client, session_factory, db):
    client.put("/settings/allowlist", json={"allowlist": "192.168.0.0/16"})

    reponse = client.put("/settings/allowlist", json={"allowlist": "  "})

    assert reponse.json()["platform_default"] is True
    assert autorise(session_factory, CLIENT, "10.1.2.3")
    assert db.query(models.WorkspaceSetting).count() == 0


def test_l_etoile_autorise_toutes_les_cibles_du_client(client, session_factory):
    client.put("/settings/allowlist", json={"allowlist": "*"})

    assert autorise(session_factory, CLIENT, "203.0.113.9")
    assert not autorise(session_factory, VOISIN, "203.0.113.9")


# ── API ──────────────────────────────────────────────────────────────────────

def test_chaque_client_lit_sa_propre_allowlist(client, session_de):
    client.put("/settings/allowlist", json={"allowlist": "192.168.0.0/16,.client.example"})

    vue_du_client = client.get("/settings/allowlist").json()
    client.app.dependency_overrides[require_auth] = lambda: session_de(VOISIN, "admin", email="admin@voisin.example")
    vue_du_voisin = client.get("/settings/allowlist").json()

    assert vue_du_client == {
        "raw": "192.168.0.0/16,.client.example", "entries": ["192.168.0.0/16", ".client.example"],
        "cidrs": ["192.168.0.0/16"], "domains": [".client.example"], "count": 2, "platform_default": False,
    }
    assert (vue_du_voisin["entries"], vue_du_voisin["platform_default"]) == ([DEFAUT_PLATEFORME], True)


@pytest.mark.parametrize("valeur", ["10.0.0.0/8,pas un domaine", "*,10.0.0.0/8", "300.1/8"])
def test_une_allowlist_invalide_est_refusee_sans_rien_changer(client, db, valeur):
    reponse = client.put("/settings/allowlist", json={"allowlist": valeur})

    assert reponse.status_code == 400
    assert db.query(models.WorkspaceSetting).count() == 0


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_seul_l_admin_du_client_change_son_allowlist(client, db, session_de, role):
    client.app.dependency_overrides[require_auth] = lambda: session_de(CLIENT, role, email=f"{role}@client.example")

    reponse = client.put("/settings/allowlist", json={"allowlist": "0.0.0.0/0"})

    assert reponse.status_code == 403
    assert db.query(models.WorkspaceSetting).count() == 0
