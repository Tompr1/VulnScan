"""
Purge du passage au MSP : tout part, sauf le référentiel commun et le compte
admin par défaut, qui retrouve un client vide.
"""
import json

import pytest
from sqlalchemy import text

from app import purge as purge_module
from app.access.domain import Role
from app.access.repository import SqlAccessRepository
from app.db import models
from app.purge import plan, purge, purge_graph, purge_queues, purge_reports
from tests.integration.conftest import POSTGRES_URL

pytestmark = pytest.mark.integration

ADMIN = "admin@local"


@pytest.fixture
def plateforme(db):
    """Deux clients avec leurs données, trois comptes, le référentiel commun."""
    db.add_all([models.Workspace(id=1, name="default"), models.Workspace(id=7, name="Client B")])
    db.add_all([
        models.User(id=1, email=ADMIN, password_hash="secret-admin", is_global_admin=False),
        models.User(id=2, email="tech@msp.example", password_hash="x"),
        models.User(id=3, email="viewer@b.example", password_hash="x"),
        models.UserGroup(id=1, name="N1"),
        models.ClientGroup(id=1, name="Tous"),
        models.CveDataset(id=1, name="CISA KEV", kind="cisa_kev", path="/data/cve/kev.json"),
        models.PlatformSetting(key="dataset_refresh", value_json=json.dumps({"enabled": True})),
    ])
    db.flush()
    db.add_all([
        models.UserGroupMember(user_group_id=1, user_id=2),
        models.ClientGroupMember(client_group_id=1, workspace_id=7),
        models.AccessGrant(user_id=2, workspace_id=1, role="analyst"),
        models.AccessGrant(user_group_id=1, client_group_id=1, role="viewer"),
        models.Profile(id=1, workspace_id=7, name="P", plugin_selection_json="{}", options_json="{}"),
        models.Asset(workspace_id=7, name="srv"),
        models.WorkspaceSetting(workspace_id=7, key="scan_allowlist", value_json='{"entries": []}'),
        models.AuditLog(workspace_id=7, actor_email="tech@msp.example", action="POST /scan/jobs"),
        models.ScanJob(id=1, workspace_id=7, target="10.0.0.1", status="done", created_by_user_id=2),
    ])
    db.flush()
    db.add(models.Finding(id=1, workspace_id=7, job_id=1, target="10.0.0.1", plugin_id="p", title="f",
                          severity="high", fingerprint="fp"))
    db.commit()


def test_l_apercu_compte_ce_qui_partira_sans_rien_supprimer(db, plateforme):
    apercu = plan(db, ADMIN)

    assert apercu.rows["users"] == 2
    assert apercu.rows["workspaces"] == 2
    assert apercu.rows["findings"] == 1
    assert "cve_datasets" not in apercu.rows and "platform_settings" not in apercu.rows
    assert apercu.kept_admin == ADMIN
    assert db.query(models.User).count() == 3


def test_la_purge_ne_laisse_que_l_admin_global_un_client_vide_et_le_referentiel(db, plateforme):
    purge(db, ADMIN, "default")

    db.expire_all()
    [admin] = db.query(models.User).all()
    assert (admin.email, admin.password_hash, admin.is_global_admin) == (ADMIN, "secret-admin", True)
    [client] = db.query(models.Workspace).all()
    assert client.name == "default"
    for model in (models.AccessGrant, models.UserGroup, models.UserGroupMember, models.ClientGroup,
                  models.ClientGroupMember, models.ScanJob, models.Finding, models.Asset, models.Profile,
                  models.WorkspaceSetting, models.AuditLog):
        assert db.query(model).count() == 0, model.__tablename__
    assert [d.name for d in db.query(models.CveDataset)] == ["CISA KEV"]
    assert db.query(models.PlatformSetting).count() == 1
    assert SqlAccessRepository(db).access_of(admin).roles == {client.id: Role.ADMIN}


@pytest.mark.skipif(not POSTGRES_URL, reason="SQLite réutilise les identifiants libérés ; la production est sur PostgreSQL")
def test_un_client_cree_apres_la_purge_ne_reprend_pas_l_identifiant_d_un_ancien(db, plateforme):
    db.execute(text("SELECT setval('workspaces_id_seq', 7)"))  # les ids 1 et 7 ont été insérés à la main
    purge(db, ADMIN, "default")

    nouveau = models.Workspace(name="Initech")
    db.add(nouveau)
    db.commit()

    assert min(w.id for w in db.query(models.Workspace)) > 7


def test_sans_admin_par_defaut_la_purge_laisse_le_demarrage_le_recreer(db, plateforme):
    purge(db, "absent@local", "default")

    assert db.query(models.User).count() == 0
    assert db.query(models.Workspace).count() == 1


def test_les_rapports_generes_sont_supprimes(tmp_path):
    (tmp_path / "vulnscan-auto-1.pdf").write_bytes(b"%PDF")
    (tmp_path / "client-b").mkdir()
    (tmp_path / "client-b" / "r.pdf").write_bytes(b"%PDF")

    assert purge_reports(str(tmp_path)) == 2
    assert list(tmp_path.iterdir()) == []
    assert purge_reports(str(tmp_path / "absent")) == 0


def test_un_service_injoignable_est_signale_sans_faire_echouer_la_purge():
    assert purge_graph("bolt://127.0.0.1:1", "neo4j", "x") is False
    assert purge_queues("redis://127.0.0.1:1/0") is False


def test_sans_yes_rien_n_est_supprime(session_factory, plateforme, monkeypatch, capsys):
    monkeypatch.setattr("app.db.session.SessionLocal", session_factory)
    monkeypatch.setattr("app.core.config.settings.DEFAULT_ADMIN_EMAIL", ADMIN)

    assert purge_module.main([]) == 0

    assert "Nothing deleted" in capsys.readouterr().out
    with session_factory() as db:
        assert db.query(models.User).count() == 3
