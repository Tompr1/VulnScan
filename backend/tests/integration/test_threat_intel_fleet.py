"""
Threat Intel croisé avec le parc du client : quelles CVE du catalogue sont
présentes sur ses appareils et ses cibles scannées, et où. Seul l'état
actuel compte (dernier scan terminé de chaque cible), jamais un scan
remplacé depuis, un constat masqué ou un appareil retiré.
"""
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.deps import get_db
from app.api.routes_threat_intel import router
from app.core.auth import require_auth
from app.db import models
from app.risk.severity import Severity
from app.scan_jobs.processing import ProcessedFinding
from app.scan_jobs.repository import SqlScanJobRepository
from app.threat_intel import aggregator, exposure

pytestmark = pytest.mark.integration

FIN = datetime(2026, 11, 27, 8, 0, tzinfo=timezone.utc)


def constat(titre, cve_ids, empreinte=None, gravite=Severity.HIGH, device_id=None):
    return ProcessedFinding(
        plugin_id="p", title=titre, severity=gravite, description="", remediation="", evidence="",
        fingerprint=empreinte or f"fp-{titre}", references=[], cvss=8.0, risk_score=8.0 if gravite is Severity.HIGH else 9.5,
        confidence=1.0, sla_days=7, compliance=[], is_kev=False, cve=None, device_id=device_id, cve_ids=tuple(cve_ids),
    )


@pytest.fixture
def parc(db, session_factory, workspace):
    db.add_all([
        models.ThreatIntelCve(cve=cve, summary=cve, severity="high", base_score=score)
        for cve, score in [("CVE-2024-0001", 90.0), ("CVE-2024-0002", 80.0), ("CVE-2024-0003", 70.0), ("CVE-2024-0004", 60.0)]
    ])
    db.add_all([
        models.Asset(id=3, workspace_id=1, name="ERP"),
        models.InventoryConnection(id=1, workspace_id=1, name="Corp", tenant_id="t", client_id="c", client_secret_enc="x"),
        models.InventoryDevice(id=7, workspace_id=1, connection_id=1, external_id="d7", name="PC-COMPTA", platform="windows"),
        models.InventoryDevice(id=8, workspace_id=1, connection_id=1, external_id="d8", name="PC-RETIRE", platform="windows",
                               removed_at=FIN),
        # Un ancien scan de l'ERP, remplacé par le suivant ; un en cours.
        models.ScanJob(id=10, workspace_id=1, target="10.0.0.5", profile_id=5, asset_id=3, status="done", scan_type="internal"),
        models.ScanJob(id=11, workspace_id=1, target="10.0.0.5", profile_id=5, asset_id=3, status="done", scan_type="internal",
                       finished_at=FIN),
        models.ScanJob(id=12, workspace_id=1, target="10.0.0.5", profile_id=5, asset_id=3, status="running", scan_type="internal"),
        models.ScanJob(id=20, workspace_id=1, target="intune:Corp", status="done", scan_type="inventory", finished_at=FIN),
        # Un autre client.
        models.ScanJob(id=30, workspace_id=2, target="10.9.9.9", profile_id=6, status="done", scan_type="internal"),
    ])
    db.commit()
    depot = SqlScanJobRepository(session_factory)
    depot.save_findings(depot.load_job(10), [constat("Ancien Apache", ["CVE-2024-0002"])])
    depot.save_findings(depot.load_job(11), [
        constat("Apache", ["CVE-2024-0001"]),
        constat("Apache RCE", ["CVE-2024-0001"], gravite=Severity.CRITICAL),
        constat("Bruit masqué", ["CVE-2024-0004"], empreinte="fp-masque"),
    ])
    depot.save_findings(depot.load_job(12), [constat("Pas fini", ["CVE-2024-0003"])])
    depot.save_findings(depot.load_job(20), [
        constat("Chrome — PC-COMPTA", ["CVE-2024-0001"], device_id=7),
        constat("Chrome — PC-RETIRE", ["CVE-2024-0003"], device_id=8),
    ])
    depot.save_findings(depot.load_job(30), [constat("Autre client", ["CVE-2024-0003"])])
    db.add(models.SuppressedFinding(workspace_id=1, fingerprint="fp-masque"))
    db.commit()


def test_les_cve_d_un_constat_sont_liees_a_l_enregistrement(parc, db):
    liens = db.query(models.FindingCve.cve, models.Finding.title).join(models.Finding, models.Finding.id == models.FindingCve.finding_id)

    assert ("CVE-2024-0001", "Apache") in liens.all()
    assert db.query(models.FindingCve).filter_by(workspace_id=2).count() == 1


def test_seule_l_etat_actuel_du_parc_compte(parc, db):
    """Remplacé (0002), masqué (0004), appareil retiré ou scan en cours (0003),
    autre client (0003) : seule 0001 est sur le parc."""
    resultat = aggregator.query(db, fleet_workspace=1, on_fleet_only=True)

    assert [c["cve"] for c in resultat["cves"]] == ["CVE-2024-0001"]
    assert resultat["total"] == 1
    assert resultat["cves"][0]["affected"] == 2  # l'ERP et PC-COMPTA


def test_sans_le_filtre_chaque_cve_indique_sa_presence_sur_le_parc(parc, db):
    resultat = aggregator.query(db, fleet_workspace=1)

    assert {c["cve"]: c["affected"] for c in resultat["cves"]} == {
        "CVE-2024-0001": 2, "CVE-2024-0002": 0, "CVE-2024-0003": 0, "CVE-2024-0004": 0,
    }


def test_hors_client_le_catalogue_n_indique_pas_de_presence(parc, db):
    assert "affected" not in aggregator.query(db)["cves"][0]


def test_les_actifs_touches_sont_listes_du_plus_urgent_au_moins_urgent(parc, db):
    resultat = exposure.affected_places(db, 1, "cve-2024-0001")

    assert (resultat["cve"], resultat["total"], resultat["truncated"]) == ("CVE-2024-0001", 2, False)
    erp, pc = resultat["places"]
    assert (erp["kind"], erp["target"], erp["asset_name"], erp["job_id"], erp["severity"]) == (
        "target", "10.0.0.5", "ERP", 11, "critical",
    )
    assert [f["title"] for f in erp["findings"]] == ["Apache RCE", "Apache"]
    assert (pc["kind"], pc["device_id"], pc["device_name"], pc["platform"], pc["job_id"]) == (
        "device", 7, "PC-COMPTA", "windows", 20,
    )


def test_un_autre_client_ne_voit_pas_ces_actifs(parc, db):
    assert exposure.affected_places(db, 2, "CVE-2024-0001")["places"] == []
    assert [p["target"] for p in exposure.affected_places(db, 2, "CVE-2024-0003")["places"]] == ["10.9.9.9"]


# ── API ──────────────────────────────────────────────────────────────────────

@pytest.fixture
def api(session_factory):
    session = {}
    app = FastAPI()
    app.include_router(router)

    def test_db():
        with session_factory() as s:
            yield s

    app.dependency_overrides.update({get_db: test_db, require_auth: lambda: session["claims"]})

    def ouvrir(claims):
        session["claims"] = claims
        return TestClient(app)

    return ouvrir


def test_l_api_filtre_sur_le_parc_du_client_ouvert(parc, api, session_de):
    client = api(session_de(1, "viewer"))

    reponse = client.get("/threat-intel/cves", params={"on_fleet": "true"})

    assert reponse.status_code == 200, reponse.text
    assert [(c["cve"], c["affected"]) for c in reponse.json()["cves"]] == [("CVE-2024-0001", 2)]
    lieux = client.get("/threat-intel/cves/CVE-2024-0001/affected").json()["places"]
    assert [p["device_name"] or p["target"] for p in lieux] == ["10.0.0.5", "PC-COMPTA"]


def test_sur_root_le_filtre_sur_le_parc_est_refuse(parc, api, db):
    admin = models.User(email="root@corp.local", password_hash="x", is_global_admin=True)
    db.add(admin)
    db.commit()
    client = api({"uid": admin.id, "sub": admin.email})

    assert client.get("/threat-intel/cves").status_code == 200
    assert client.get("/threat-intel/cves", params={"on_fleet": "true"}).status_code == 400
    assert client.get("/threat-intel/cves/CVE-2024-0001/affected").status_code == 403
