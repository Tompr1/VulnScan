"""
Inventory audit end to end: an inventory job runs through the real runner,
finding pipeline and SQL storage, then the device API shows each device's
issues. Only Microsoft Graph (inventory pre-seeded) and endoflife.date
(canned catalog) are replaced.
"""
import json
from datetime import date, datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.routes_inventory import get_inventory_read_model, router
from app.core.auth import require_auth
from app.core.job_queue import get_job_queue
from app.db import models
from app.inventory.audit.auditor import DeviceAuditor
from app.inventory.audit.rules import default_rules
from app.inventory.audit.service import InventoryAudit
from app.inventory.domain import Device, InstalledApp, InventorySnapshot, Platform
from app.inventory.repository import SqlInventoryReadModel, SqlInventoryRepository
from app.inventory.sync import InventorySync
from app.scan_jobs.executors import InventoryScanExecutor
from app.scan_jobs.filtering import FindingFilterPolicy
from app.scan_jobs.processing import FindingProcessor
from app.scan_jobs.repository import SqlScanJobRepository
from app.scan_jobs.runner import ScanJobRunner
from app.scanner.target import ScanType
from tests.fakes import SpyGraph, SpyJobQueue, SpyNotifier, StubAiTrigger, no_compliance
from tests.unit.inventory.eol_fixtures import StaticSupportCatalog

pytestmark = pytest.mark.integration

SYNCED_AT = datetime(2026, 11, 21, 5, 0, tzinfo=timezone.utc)


@pytest.fixture
def client(session_factory, workspace):
    app = FastAPI()
    app.include_router(router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides.update({
        get_db: test_db,
        require_auth: lambda: {"ws": 1, "uid": None, "sub": "admin@corp.local", "role": "admin"},
        get_job_queue: SpyJobQueue,
        get_inventory_read_model: lambda: SqlInventoryReadModel(session_factory),
    })
    return TestClient(app)


def create(client):
    response = client.post("/inventory/connections", json={
        "name": "Tenant de test", "tenant_id": "11111111-2222-3333-4444-555555555555",
        "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "client_secret": "s3cr3t~value",
    })
    assert response.status_code == 201, response.text
    return response.json()


class AlreadyCollected:
    """The inventory is seeded by the test: collection is a no-op."""

    def collect(self, connection_id, workspace_id):
        return None


def seed(session_factory, connection_id):
    snapshot = InventorySnapshot("intune", (
        Device("d1", "PC-COMPTA-04", Platform.WINDOWS, os_name="Windows", os_version="10.0.22631.4317",
               user_principal_name="j.martin@corp.example", apps=(InstalledApp("Notepad++ (64-bit x64)", "8.9.2"),)),
        Device("d2", "PC-RH-01", Platform.WINDOWS, os_name="Windows", os_version="10.0.26200.7171"),
        Device("d3", "Pixel de A. Durand", Platform.ANDROID, os_name="Android", os_version="16", security_patch_level="2026-11-01"),
    ), SYNCED_AT)
    InventorySync(SqlInventoryRepository(session_factory)).apply(connection_id, 1, snapshot)


def add_inventory_job(db, connection_id, job_id, status="queued"):
    db.add(models.ScanJob(
        id=job_id, workspace_id=1, target="intune:Tenant de test", status=status, scan_type="inventory",
        meta_json=json.dumps({"inventory_connection_id": connection_id}),
    ))
    db.commit()


def run_inventory_job(session_factory, job_id, catalog=None):
    audit = InventoryAudit(
        SqlInventoryRepository(session_factory),
        DeviceAuditor(default_rules(), lambda: catalog or StaticSupportCatalog(), today=lambda: date(2026, 11, 21)),
    )
    ScanJobRunner(
        repository=SqlScanJobRepository(session_factory),
        executors={ScanType.INVENTORY: InventoryScanExecutor(AlreadyCollected, lambda: audit)},
        processor_factory=lambda job, profile: FindingProcessor(FindingFilterPolicy(), no_compliance),
        notifier=SpyNotifier(),
        graph_factory=SpyGraph,
        ai_trigger=StubAiTrigger(queues=True),
    ).run(job_id)


@pytest.fixture
def audited(client, session_factory, db):
    connection = create(client)
    seed(session_factory, connection["id"])
    add_inventory_job(db, connection["id"], job_id=100)
    run_inventory_job(session_factory, 100)
    db.expire_all()
    return connection


def device_id(db, name):
    return db.query(models.InventoryDevice).filter_by(name=name).one().id


def test_le_job_d_inventaire_enregistre_les_constats_lies_aux_appareils(audited, db):
    job = db.get(models.ScanJob, 100)
    findings = db.query(models.Finding).filter_by(job_id=100).order_by(models.Finding.plugin_id).all()

    assert job.status == "done"  # not "analyzing": no automatic AI analysis
    assert [(f.plugin_id, f.device_id) for f in findings] == [
        ("inventory.app_outdated", device_id(db, "PC-COMPTA-04")),
        ("inventory.os_unsupported", device_id(db, "PC-COMPTA-04")),
    ]
    assert findings[1].severity == "high" and findings[1].sla_days is not None
    run = db.query(models.InventoryAuditRun).one()
    assert (run.connection_id, run.job_id, run.devices, run.issues, run.warnings) == (audited["id"], 100, 3, 2, "")


def test_la_liste_des_appareils_resume_leurs_problemes(audited, client):
    devices = {d["name"]: d for d in client.get("/inventory/devices").json()}

    assert (devices["PC-COMPTA-04"]["issue_count"], devices["PC-COMPTA-04"]["highest_severity"]) == (2, "high")
    assert (devices["PC-RH-01"]["issue_count"], devices["PC-RH-01"]["highest_severity"]) == (0, None)


def test_la_fiche_appareil_detaille_les_problemes_du_dernier_audit(audited, client, db):
    detail = client.get(f"/inventory/devices/{device_id(db, 'PC-COMPTA-04')}").json()

    assert detail["last_audit"] == {"job_id": 100, "audited_at": detail["last_audit"]["audited_at"], "devices": 3, "issues": 2, "warnings": []}
    assert [issue["rule"] for issue in detail["issues"]] == ["os_unsupported", "app_outdated"]  # riskiest first
    unsupported = detail["issues"][0]
    assert unsupported["title"] == "Windows 11 23H2 (W) is no longer supported — PC-COMPTA-04"
    assert "User: j.martin@corp.example" in unsupported["evidence"]
    assert unsupported["references"] == ["https://endoflife.date/windows"]


def test_un_audit_en_cours_ne_remplace_pas_le_dernier_audit_termine(audited, client, db):
    db.add(models.ScanJob(id=101, workspace_id=1, target="intune:Tenant de test", status="running", scan_type="inventory"))
    db.add(models.InventoryAuditRun(connection_id=audited["id"], job_id=101, audited_at=SYNCED_AT, devices=3, issues=0))
    db.commit()

    detail = client.get(f"/inventory/devices/{device_id(db, 'PC-COMPTA-04')}").json()
    devices = {d["name"]: d for d in client.get("/inventory/devices").json()}

    assert detail["last_audit"]["job_id"] == 100
    assert len(detail["issues"]) == 2
    assert devices["PC-COMPTA-04"]["issue_count"] == 2


def test_un_appareil_jamais_audite_n_a_ni_audit_ni_probleme(client, session_factory, db):
    connection = create(client)
    seed(session_factory, connection["id"])

    detail = client.get(f"/inventory/devices/{device_id(db, 'PC-COMPTA-04')}").json()

    assert (detail["last_audit"], detail["issues"]) == (None, [])


def test_un_audit_incomplet_est_visible_sur_l_audit_et_dans_les_constats(client, session_factory, db):
    connection = create(client)
    seed(session_factory, connection["id"])
    add_inventory_job(db, connection["id"], job_id=100)

    run_inventory_job(session_factory, 100, StaticSupportCatalog(unavailable=("windows",)))

    detail = client.get(f"/inventory/devices/{device_id(db, 'PC-RH-01')}").json()
    assert detail["last_audit"]["warnings"][0].startswith("Support lifecycle unavailable (endoflife.date) for: windows.")
    assert db.query(models.Finding).filter_by(job_id=100, plugin_id="inventory.audit_incomplete").count() == 1


def test_un_probleme_supprime_par_l_utilisateur_n_est_plus_enregistre(audited, session_factory, db):
    unsupported = db.query(models.Finding).filter_by(job_id=100, plugin_id="inventory.os_unsupported").one()
    db.add(models.SuppressedFinding(workspace_id=1, fingerprint=unsupported.fingerprint, reason="Poste en cours de remplacement"))
    add_inventory_job(db, audited["id"], job_id=101)

    run_inventory_job(session_factory, 101)

    assert [f.plugin_id for f in db.query(models.Finding).filter_by(job_id=101)] == ["inventory.app_outdated"]


def test_supprimer_la_connexion_garde_les_constats_mais_retire_le_lien_et_les_audits(audited, client, db):
    client.delete(f"/inventory/connections/{audited['id']}")

    db.expire_all()
    assert db.query(models.InventoryAuditRun).count() == 0
    assert [f.device_id for f in db.query(models.Finding).filter_by(job_id=100)] == [None, None]
