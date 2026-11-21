import json
from datetime import datetime, timezone

import pytest

from app.risk.severity import Severity
from app.scan_jobs.processing import ProcessedFinding
from app.scan_jobs.repository import JobCompletion, JobFailure, SqlIntegrationSource, SqlScanJobRepository
from app.db import models

pytestmark = pytest.mark.integration

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def repository(session_factory):
    return SqlScanJobRepository(session_factory)


@pytest.fixture
def job(db, workspace):
    row = models.ScanJob(
        id=10, workspace_id=1, target="10.0.0.5", profile_id=5, status="queued", scan_type=None,
        meta_json=json.dumps({"web_auth": {"type": "basic", "credential_id": 3}, "web_auth_credential_ephemeral": True}),
    )
    db.add(row)
    db.commit()
    return row


def processed(title: str) -> ProcessedFinding:
    return ProcessedFinding(
        plugin_id="p", title=title, severity=Severity.HIGH, description="d\x00", remediation="r",
        evidence="e", fingerprint="fp", references=["https://ref"], cvss=8.0, risk_score=8.0,
        confidence=1.0, sla_days=7, compliance=["NIST-SI-2"], is_kev=False, cve=None,
    )


def test_un_job_est_relu_sous_forme_de_copie_independante_de_la_session(repository, job):
    snapshot = repository.load_job(10)

    assert (snapshot.target, snapshot.scan_type, snapshot.ephemeral_credential_id) == ("10.0.0.5", "internal", 3)


def test_un_job_inexistant_n_est_pas_trouve(repository, workspace):
    assert repository.load_job(404) is None


def test_un_profil_n_est_charge_que_dans_son_workspace(repository, workspace):
    assert repository.load_profile(1, 5) is not None
    assert repository.load_profile(1, 6) is None


def test_le_cycle_de_vie_d_un_job_est_persiste(repository, job, db):
    repository.mark_running(10, NOW)
    repository.mark_done(10, JobCompletion(4, 3, 1, 0.2), NOW)

    db.expire_all()
    row = db.get(models.ScanJob, 10)
    assert row.status == "done"
    assert json.loads(row.meta_json) == {"findings_total": 4, "findings_saved": 3, "findings_dropped": 1, "min_confidence_threshold": 0.2}


def test_un_echec_conserve_le_detail_et_une_trace_tronquee(repository, job, db):
    repository.mark_failed(10, JobFailure("boom", "scan_engine", "detail", "x" * 5000), NOW)

    db.expire_all()
    meta = json.loads(db.get(models.ScanJob, 10).meta_json)
    assert (meta["error"], meta["error_type"], meta["error_detail"], len(meta["traceback"])) == ("boom", "scan_engine", "detail", 2000)


def test_les_octets_nuls_sont_retires_avant_l_enregistrement(repository, job, db):
    repository.save_findings(repository.load_job(10), [processed("XSS")])

    row = db.query(models.Finding).one()
    assert (row.description, row.severity, json.loads(row.compliance_json)) == ("d", "high", ["NIST-SI-2"])


def test_les_empreintes_masquees_sont_propres_au_workspace(repository, db, workspace):
    db.add_all([models.SuppressedFinding(workspace_id=1, fingerprint="a"), models.SuppressedFinding(workspace_id=2, fingerprint="b")])
    db.commit()

    assert repository.suppressed_fingerprints(1) == {"a"}


def test_un_identifiant_ephemere_n_est_supprime_que_dans_le_workspace_du_job(repository, job, db):
    db.add_all([
        models.Credential(id=3, workspace_id=1, name="mine", username="u", secret_enc="s"),
        models.Credential(id=4, workspace_id=2, name="other", username="u", secret_enc="s"),
    ])
    db.commit()

    repository.delete_ephemeral_credential(repository.load_job(10))

    db.expire_all()
    assert [c.id for c in db.query(models.Credential).all()] == [4]


def test_seules_les_integrations_actives_et_bien_configurees_sont_utilisees(session_factory, db, workspace):
    db.add_all([
        models.Integration(workspace_id=1, provider="slack", enabled=True, config_json='{"url": "s"}'),
        models.Integration(workspace_id=1, provider="email", enabled=False, config_json='{"to": "e"}'),
        models.Integration(workspace_id=1, provider="webhook", enabled=True, config_json="not json"),
    ])
    db.commit()

    integrations = SqlIntegrationSource(session_factory).enabled_integrations(1)

    assert [(i.provider, i.config) for i in integrations] == [("slack", {"url": "s"})]
