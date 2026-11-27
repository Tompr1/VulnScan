"""La découverte signale les hôtes déjà présents dans les assets."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_analytics
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.db import models

pytestmark = pytest.mark.integration


@pytest.fixture
def client(session_factory, db, workspace, session_de, monkeypatch):
    db.add(models.Asset(id=70, workspace_id=1, name="Routeur box"))
    db.add(models.Asset(id=71, workspace_id=1, name="Imprimante"))
    db.add(models.AssetTarget(id=80, workspace_id=1, asset_id=70, target="192.168.3.1"))
    db.add(models.ScanJob(id=81, workspace_id=1, target="192.168.3.5", profile_id=5, asset_id=71))
    db.add(models.AssetTarget(id=82, workspace_id=2, asset_id=70, target="192.168.3.9"))  # autre client
    db.commit()

    monkeypatch.setattr(routes_analytics, "discover_hosts", lambda net: [
        {"ip": "192.168.3.1", "hostname": None},
        {"ip": "192.168.3.5", "hostname": None},
        {"ip": "192.168.3.9", "hostname": None},
        {"ip": "192.168.3.10", "hostname": "nouveau.lan"},
    ])
    claims = session_de(1, "admin")
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_analytics.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides.update({get_db: test_db, require_auth: lambda: claims})
    return TestClient(app, raise_server_exceptions=False)


def test_hosts_already_on_an_asset_are_flagged_with_it(client):
    reponse = client.post("/analytics/discover", json={"network_range": "192.168.3.0/24"})

    assert reponse.status_code == 200, reponse.text
    par_ip = {h["ip"]: h for h in reponse.json()["hosts"]}
    assert (par_ip["192.168.3.1"]["asset_id"], par_ip["192.168.3.1"]["asset_name"]) == (70, "Routeur box")
    assert (par_ip["192.168.3.5"]["asset_id"], par_ip["192.168.3.5"]["asset_name"]) == (71, "Imprimante")


def test_new_hosts_and_other_workspaces_are_not_flagged(client):
    reponse = client.post("/analytics/discover", json={"network_range": "192.168.3.0/24"})

    par_ip = {h["ip"]: h for h in reponse.json()["hosts"]}
    assert par_ip["192.168.3.10"]["asset_id"] is None
    assert par_ip["192.168.3.9"]["asset_id"] is None  # cible d'un autre client
