"""Enregistrer des hôtes découverts comme assets, chacun avec sa cible."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import routes_assets
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.db import models

pytestmark = pytest.mark.integration


@pytest.fixture
def base(db, workspace):
    db.add(models.Credential(id=50, workspace_id=1, name="ssh-lab", username="root",
                             secret_enc="x"))
    db.add(models.Asset(id=60, workspace_id=1, name="Labo"))
    db.commit()


@pytest.fixture
def client(session_factory, base, session_de):
    claims = session_de(1, "admin")
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_assets.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides.update({get_db: test_db, require_auth: lambda: claims})
    return TestClient(app, raise_server_exceptions=False)


def _hote(ip, name=None, **extra):
    return {"name": name or ip, "target": ip, **extra}


def test_creates_one_asset_per_host_with_its_target(client, db):
    reponse = client.post("/assets/from-hosts", json={"assets": [
        _hote("192.168.3.10", "poste-compta", parent_id=60, default_credential_id=50),
        _hote("192.168.3.11"),
    ]})

    assert reponse.status_code == 200, reponse.text
    crees = reponse.json()
    assert [a["name"] for a in crees] == ["poste-compta", "192.168.3.11"]
    assert crees[0]["parent_id"] == 60 and crees[0]["default_credential_id"] == 50
    assert crees[0]["targets"] == 1

    cibles = db.scalars(select(models.AssetTarget.target).order_by(models.AssetTarget.target)).all()
    assert cibles == ["192.168.3.10", "192.168.3.11"]


def test_asset_list_carries_its_targets(client):
    client.post("/assets/from-hosts", json={"assets": [_hote("10.1.2.4")]})

    liste = client.get("/assets").json()

    par_nom = {a["name"]: a["target_list"] for a in liste}
    assert par_nom == {"Labo": [], "10.1.2.4": ["10.1.2.4"]}


def test_target_of_a_new_asset_is_listed_before_any_scan(client):
    asset_id = client.post("/assets/from-hosts", json={"assets": [_hote("10.1.2.3")]}).json()[0]["id"]

    cibles = client.get(f"/assets/{asset_id}/targets").json()

    assert [(c["target"], c["scans"]) for c in cibles] == [("10.1.2.3", 0)]


def test_one_bad_entry_creates_nothing(client, db):
    reponse = client.post("/assets/from-hosts", json={"assets": [
        _hote("192.168.3.10"),
        _hote("192.168.3.11", parent_id=999),  # dossier inconnu
    ]})

    assert reponse.status_code == 400
    assert db.scalars(select(models.Asset).where(models.Asset.name == "192.168.3.10")).first() is None


@pytest.mark.parametrize("cible", ["8.8.8.8", "fd00::1", "pas-une-ip"])
def test_only_private_ipv4_addresses_are_accepted(client, cible):
    reponse = client.post("/assets/from-hosts", json={"assets": [_hote(cible)]})

    assert reponse.status_code == 400


def test_name_is_required(client):
    reponse = client.post("/assets/from-hosts", json={"assets": [_hote("10.0.0.7", name="  ")]})

    assert reponse.status_code == 400


def test_credential_of_another_workspace_is_refused(client, db):
    db.add(models.Credential(id=70, workspace_id=2, name="autre", username="u", secret_enc="x"))
    db.commit()

    reponse = client.post("/assets/from-hosts", json={"assets": [_hote("10.0.0.8", default_credential_id=70)]})

    assert reponse.status_code == 400


def test_adding_the_same_host_twice_is_refused_and_creates_nothing(client, db):
    assert client.post("/assets/from-hosts", json={"assets": [_hote("10.0.0.9", "nas")]}).status_code == 200

    reponse = client.post("/assets/from-hosts", json={"assets": [_hote("10.0.0.10"), _hote("10.0.0.9", "nas-bis")]})

    assert reponse.status_code == 409
    assert '10.0.0.9 (asset "nas")' in reponse.json()["detail"]
    assert db.scalars(select(models.Asset.name).where(models.Asset.name.in_(["10.0.0.10", "nas-bis"]))).all() == []


def test_a_host_already_scanned_under_an_asset_is_refused(client, db):
    db.add(models.ScanJob(id=90, workspace_id=1, target="10.0.0.11", profile_id=5, asset_id=60))
    db.commit()

    reponse = client.post("/assets/from-hosts", json={"assets": [_hote("10.0.0.11")]})

    assert reponse.status_code == 409


def test_the_same_host_on_another_client_does_not_block(client, db):
    db.add(models.Asset(id=61, workspace_id=2, name="voisin"))
    db.add(models.AssetTarget(workspace_id=2, asset_id=61, target="10.0.0.12"))
    db.commit()

    assert client.post("/assets/from-hosts", json={"assets": [_hote("10.0.0.12")]}).status_code == 200


def test_targets_are_stored_normalized_and_deduplicated(client, db):
    doublon = client.post("/assets/from-hosts", json={"assets": [_hote(" 10.0.0.13"), _hote("10.0.0.13 ")]})
    cree = client.post("/assets/from-hosts", json={"assets": [_hote(" 10.0.0.14 ", "poste")]})

    assert doublon.status_code == 400
    assert cree.status_code == 200
    assert db.scalars(select(models.AssetTarget.target).where(models.AssetTarget.asset_id == cree.json()[0]["id"])).all() == ["10.0.0.14"]
