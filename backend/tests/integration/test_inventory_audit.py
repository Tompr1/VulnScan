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
from app.core.workspace_settings import set_workspace_setting
from app.cve.nvd import parse_vulnerability
from app.cve.nvd_sync import SyncState
from app.cve.sql_catalog import SqlCveCatalog, SqlSyncStateStore
from app.db import models
from app.inventory.alerts import DeviceLinks, InventoryAlerter
from app.inventory.audit.auditor import DeviceAuditor
from app.inventory.audit.reference import NO_KEV_DATASET, NVD_IMPORT_RUNNING, workspace_reference_data
from app.inventory.audit.rules import default_rules
from app.inventory.audit.service import InventoryAudit
from app.inventory.domain import Device, InstalledApp, InventorySnapshot, Platform
from app.inventory.repository import SqlAlertHistory, SqlInventoryReadModel, SqlInventoryRepository
from app.inventory.sync import InventorySync
from app.scan_jobs.executors import InventoryScanExecutor
from app.scan_jobs.filtering import FindingFilterPolicy
from app.scan_jobs.processing import FindingProcessor
from app.scan_jobs.repository import SqlIntegrationSource, SqlScanJobRepository
from app.scan_jobs.runner import ScanJobRunner
from app.scanner.target import ScanType
from tests.fakes import SpyGraph, SpyJobQueue, SpyNotifier, StubAiTrigger, no_compliance
from tests.unit.cve.nvd_fixtures import nvd_entry
from tests.unit.inventory.eol_fixtures import StaticSupportCatalog, reference_data

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
        DeviceAuditor(default_rules(), today=lambda: date(2026, 11, 21)),
        lambda workspace_id: reference_data(catalog),
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


# ── Known vulnerabilities, from the real SQL catalog and a KEV dataset ────────

def store_cves(session_factory, *entries, import_done=True):
    SqlCveCatalog(session_factory).upsert([parse_vulnerability(entry) for entry in entries])
    if import_done:
        SqlSyncStateStore(session_factory).save(SyncState(full_import_completed_at=SYNCED_AT))


def load_kev(db, tmp_path, *rows):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(list(rows)))
    db.add(models.CveDataset(workspace_id=1, name="CISA KEV", kind="cisa_kev", path=str(path), enabled=True))
    db.commit()


def run_with_workspace_reference(session_factory, job_id):
    audit = InventoryAudit(
        SqlInventoryRepository(session_factory),
        DeviceAuditor(default_rules(), today=lambda: date(2026, 11, 21)),
        lambda workspace_id: workspace_reference_data(workspace_id, session_factory, lifecycle=StaticSupportCatalog),
    )
    ScanJobRunner(
        repository=SqlScanJobRepository(session_factory),
        executors={ScanType.INVENTORY: InventoryScanExecutor(AlreadyCollected, lambda: audit)},
        processor_factory=lambda job, profile: FindingProcessor(FindingFilterPolicy(), no_compliance),
        notifier=SpyNotifier(),
        graph_factory=SpyGraph,
        ai_trigger=StubAiTrigger(),
    ).run(job_id)


WINDOWS_CVE = nvd_entry("CVE-2025-1001", cvss=7.8, matches=[{
    "vulnerable": True, "criteria": "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*",
    "versionEndExcluding": "10.0.22631.6060",
}])
OFFICE_CVE = nvd_entry("CVE-2025-1002", cvss=9.8, matches=[{
    "vulnerable": True, "criteria": "cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:*:*",
}])


def test_une_cve_exploitee_sur_un_appareil_devient_un_constat_critique_lie_a_l_appareil(client, session_factory, db, tmp_path):
    connection = create(client)
    seed(session_factory, connection["id"])
    store_cves(session_factory, WINDOWS_CVE, OFFICE_CVE)
    load_kev(db, tmp_path, {"cveID": "CVE-2025-1001", "dateAdded": "2025-09-01", "dueDate": "2025-09-22",
                            "knownRansomwareCampaignUse": "Unknown"})
    add_inventory_job(db, connection["id"], job_id=100)

    run_with_workspace_reference(session_factory, 100)

    db.expire_all()
    finding = db.query(models.Finding).filter_by(job_id=100, plugin_id="inventory.os_vulnerable").one()
    assert (finding.device_id, finding.is_kev, finding.severity) == (device_id(db, "PC-COMPTA-04"), True, "critical")
    assert finding.title == ("Windows 11 23H2 10.0.22631.4317 has 1 known vulnerability, 1 actively exploited — PC-COMPTA-04")
    assert "CISA remediation deadline 2025-09-22" in finding.remediation
    assert db.query(models.InventoryAuditRun).one().warnings == ""  # complete: NVD imported, KEV loaded
    detail = client.get(f"/inventory/devices/{device_id(db, 'PC-COMPTA-04')}").json()
    assert detail["issues"][0]["rule"] == "os_vulnerable"


def test_les_lacunes_des_donnees_cve_sont_signalees_avec_l_audit(client, session_factory, db):
    connection = create(client)
    seed(session_factory, connection["id"])
    store_cves(session_factory, WINDOWS_CVE, import_done=False)
    add_inventory_job(db, connection["id"], job_id=100)

    run_with_workspace_reference(session_factory, 100)

    db.expire_all()
    warnings = db.query(models.InventoryAuditRun).one().warnings.splitlines()
    assert warnings == [NVD_IMPORT_RUNNING, NO_KEV_DATASET]
    notice = db.query(models.Finding).filter_by(job_id=100, plugin_id="inventory.audit_incomplete").one()
    assert NO_KEV_DATASET in notice.description
    # The CVE is still found from what the catalog already holds, without the KEV flag.
    vulnerable = db.query(models.Finding).filter_by(job_id=100, plugin_id="inventory.os_vulnerable").one()
    assert vulnerable.is_kev is False


# ── Alerts on new device issues ───────────────────────────────────────────────

def run_and_alert(session_factory, job_id, notifier, catalog=None):
    audit = InventoryAudit(
        SqlInventoryRepository(session_factory),
        DeviceAuditor(default_rules(), today=lambda: date(2026, 11, 21)),
        lambda workspace_id: reference_data(catalog),
    )
    ScanJobRunner(
        repository=SqlScanJobRepository(session_factory),
        executors={ScanType.INVENTORY: InventoryScanExecutor(AlreadyCollected, lambda: audit)},
        processor_factory=lambda job, profile: FindingProcessor(FindingFilterPolicy(), no_compliance),
        notifier=notifier,
        graph_factory=SpyGraph,
        ai_trigger=StubAiTrigger(),
        announcers={ScanType.INVENTORY: InventoryAlerter(SqlAlertHistory(session_factory), notifier, DeviceLinks("https://vs.example"))},
    ).run(job_id)


def resync(session_factory, connection_id, **builds):
    """A new collection: same devices, possibly other Windows builds."""
    devices = (
        Device("d1", "PC-COMPTA-04", Platform.WINDOWS, os_name="Windows", os_version=builds.get("d1", "10.0.22631.4317"),
               apps=(InstalledApp("Notepad++ (64-bit x64)", "8.9.2"),)),
        Device("d2", "PC-RH-01", Platform.WINDOWS, os_name="Windows", os_version=builds.get("d2", "10.0.26200.7171")),
    )
    InventorySync(SqlInventoryRepository(session_factory)).apply(connection_id, 1, InventorySnapshot("intune", devices, SYNCED_AT))


@pytest.fixture
def alerted(client, session_factory, db):
    connection = create(client)
    resync(session_factory, connection["id"])
    return connection


def test_le_premier_audit_envoie_un_bilan_et_pas_de_message_de_fin_de_scan(alerted, session_factory, db):
    notifier = SpyNotifier()
    add_inventory_job(db, alerted["id"], job_id=100)

    run_and_alert(session_factory, 100, notifier)

    [(workspace, alert)] = notifier.alerts
    assert (workspace, alert.baseline) == (1, True)
    # High and above only: the outdated Notepad++ (low) stays out.
    assert [(i.issue.rule, i.device_name, i.link) for i in alert.items] == [
        ("os_unsupported", "PC-COMPTA-04", f"https://vs.example/#/inventory/devices/{device_id(db, 'PC-COMPTA-04')}"),
    ]
    assert notifier.completed == []


def test_un_audit_sans_nouveaute_n_envoie_rien(alerted, session_factory, db):
    notifier = SpyNotifier()
    for job_id in (100, 101):
        add_inventory_job(db, alerted["id"], job_id=job_id)
        run_and_alert(session_factory, job_id, notifier)

    assert len(notifier.alerts) == 1  # the baseline only


def test_seul_le_nouveau_probleme_est_alerte_avec_les_problemes_resolus(alerted, session_factory, db):
    notifier = SpyNotifier()
    add_inventory_job(db, alerted["id"], job_id=100)
    run_and_alert(session_factory, 100, notifier)
    # PC-COMPTA-04 is upgraded, PC-RH-01 is reinstalled on an unsupported release.
    resync(session_factory, alerted["id"], d1="10.0.26200.7171", d2="10.0.22631.4317")
    add_inventory_job(db, alerted["id"], job_id=101)

    run_and_alert(session_factory, 101, notifier)

    alert = notifier.alerts[-1][1]
    assert (alert.baseline, [i.device_name for i in alert.items]) == (False, ["PC-RH-01"])
    assert alert.resolved == 1  # PC-COMPTA-04 no longer unsupported


def test_un_audit_dont_le_job_a_echoue_n_est_pas_la_reference(alerted, session_factory, db):
    notifier = SpyNotifier()
    add_inventory_job(db, alerted["id"], job_id=100)
    run_and_alert(session_factory, 100, notifier)
    # Job 101 audited but failed before saving its findings: no issue on record.
    add_inventory_job(db, alerted["id"], job_id=101, status="failed")
    db.add(models.InventoryAuditRun(connection_id=alerted["id"], job_id=101, audited_at=SYNCED_AT, devices=2, issues=0))
    db.commit()
    add_inventory_job(db, alerted["id"], job_id=102)

    run_and_alert(session_factory, 102, notifier)

    assert len(notifier.alerts) == 1  # compared with job 100: nothing new


def test_le_seuil_d_alerte_se_regle_par_l_api(client):
    assert client.get("/inventory/alert-settings").json() == {"min_severity": "high", "always_kev": True}

    response = client.put("/inventory/alert-settings", json={"min_severity": "critical", "always_kev": False})

    assert response.json() == {"min_severity": "critical", "always_kev": False}
    assert client.get("/inventory/alert-settings").json() == {"min_severity": "critical", "always_kev": False}


@pytest.mark.parametrize("body", [{"min_severity": "urgent"}, {"always_kev": "oui"}, {"min_severity": "high", "extra": 1}])
def test_un_seuil_d_alerte_invalide_est_refuse(client, body):
    assert client.put("/inventory/alert-settings", json=body).status_code == 422


def test_le_seuil_reglable_change_ce_qui_est_alerte(alerted, client, session_factory, db):
    client.put("/inventory/alert-settings", json={"min_severity": "low", "always_kev": True})
    notifier = SpyNotifier()
    add_inventory_job(db, alerted["id"], job_id=100)

    run_and_alert(session_factory, 100, notifier)

    assert sorted(i.issue.rule for i in notifier.alerts[0][1].items) == ["app_outdated", "os_unsupported"]


def test_les_preferences_enregistrees_avant_les_alertes_d_appareil_recoivent_leurs_valeurs_par_defaut(session_factory, db, workspace):
    set_workspace_setting(db, 1, "notification_preferences", {"scan_completed": {"email": True, "slack": False, "webhook": False}})

    preferences = SqlIntegrationSource(session_factory).notification_preferences(1)

    assert preferences["scan_completed"] == {"email": True, "slack": False, "webhook": False}
    assert preferences["device_vulnerability"] == {"email": True, "slack": True, "webhook": True}
