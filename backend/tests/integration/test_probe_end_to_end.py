"""
De bout en bout : une sonde enrôlée par la commande v0cday-probe prend un
scan de son client sur la vraie API, l'exécute avec le vrai moteur (plugin
de test), et ses constats finissent enregistrés sur la plateforme.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import routes_probe_agent, routes_probes
from app.api.deps import get_db
from app.core.auth import require_auth
from app.core.config import settings
from app.core.crypto import encrypt_str
from app.core.job_queue import ProbeAwareJobQueue
from app.db import models
from app.probe_agent import cli
from app.probe_agent.agent import FixedAllowlist, ProbeAgent, ReportOutbox
from app.probe_agent.config import ProbeConfig
from app.probe_agent.platform import PlatformClient
from app.probe_agent.reference import RemoteReferenceData
from app.probes.gateway import ProbeGateway
from app.scan_jobs.assigner import JobAssigner
from app.scan_jobs.assignment import ScanReport
from app.scan_jobs.executors import EngineScanExecutor
from app.scan_jobs.filtering import FindingFilterPolicy
from app.scan_jobs.processing import FindingProcessor
from app.scan_jobs.repository import SqlScanJobRepository
from app.scan_jobs.runner import ScanJobRunner
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.budget import ScanBudget
from app.scanner.engine import ScanEngine
from app.scanner.plugins.base import Finding, PluginResult
from app.scanner.plugins.loader import PluginRegistry
from app.scanner.sql_resources import SqlCredentialVault
from app.scanner.target import ScanType
from tests.fakes import (
    FakePlugin,
    SpyCancellationSignal,
    SpyGraph,
    SpyJobQueue,
    SpyNotifier,
    StubAiTrigger,
    StubExecutor,
    meta,
    no_compliance,
)

pytestmark = pytest.mark.integration

PLATFORM = "https://platform.example"
CLIENT = 1


class ClientAllowlists:
    def policy_for(self, workspace_id):
        return AllowlistPolicy.from_setting("10.0.0.0/8")


@pytest.fixture
def plateforme(session_factory, db, workspace, tmp_path):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps([{"cve": "CVE-2024-6387", "vendorProject": "OpenBSD"}]))
    db.add_all([
        models.User(id=1, email="root@msp.example", password_hash="x", is_global_admin=True),
        models.Credential(id=30, workspace_id=CLIENT, name="linux", username="audit",
                          secret_enc=encrypt_str("pw-linux"), secret_type="password"),
        models.CveDataset(id=1, name="kev", kind="cisa_kev", path=str(kev)),
    ])
    db.get(models.Profile, 5).options_json = json.dumps({"auth": {"ssh_credential_id": 30}})
    db.commit()

    app = FastAPI()
    app.include_router(routes_probes.router)
    app.include_router(routes_probe_agent.router)
    reports = SpyJobQueue()

    def test_db():
        with session_factory() as session:
            yield session

    gateway = ProbeGateway(
        session_factory,
        JobAssigner(SqlScanJobRepository(session_factory), lambda ws: SqlCredentialVault(session_factory, ws),
                    ClientAllowlists()),
        reports, SpyCancellationSignal(), lambda: datetime.now(timezone.utc), timedelta(hours=24),
    )
    app.dependency_overrides[get_db] = test_db
    app.dependency_overrides[require_auth] = lambda: {"uid": 1, "sub": "root@msp.example"}
    app.dependency_overrides[routes_probe_agent.get_probe_gateway] = lambda: gateway
    return app, reports


def test_un_scan_part_sur_la_sonde_du_client_et_ses_constats_reviennent(plateforme, session_factory, db, tmp_path,
                                                                       monkeypatch):
    app, reports = plateforme
    admin = TestClient(app, base_url=PLATFORM)
    monkeypatch.setattr(cli, "open_http", lambda *args, **kwargs: TestClient(app, base_url=PLATFORM))
    config_path = tmp_path / "probe.json"

    # 1. Root crée la sonde ; on l'enrôle avec la commande, comme sur la VM.
    token = admin.post("/probes", json={"workspace_id": CLIENT, "name": "Paris"}).json()["enrollment"]["token"]
    assert cli.main(["--config", str(config_path), "enroll", "--platform", PLATFORM, "--token", token]) == 0
    assert cli.main(["--config", str(config_path), "status"]) == 0
    config = ProbeConfig.load(config_path)

    # 2. Les scans internes du client vont à sa sonde ; un scan est lancé.
    admin.put(f"/probes/clients/{CLIENT}/execution", json={"scan_types": ["internal"]})
    db.add(models.ScanJob(id=40, workspace_id=CLIENT, target="10.0.0.5", profile_id=5, status="queued",
                          scan_type="internal"))
    db.commit()
    platform_workers = SpyJobQueue()
    ProbeAwareJobQueue(session_factory, platform_workers).enqueue_scan(40)

    # 3. La sonde le prend et l'exécute avec le vrai moteur.
    seen = {}

    def audit(ctx):
        seen["secret"] = ctx.resources.credentials.get(30).secret
        seen["kev"] = ctx.resources.reference.datasets("cisa_kev")

    plugin = FakePlugin(meta("test.audit"), findings=[Finding("test.audit", "Service exposé", severity="high")],
                        on_run=audit)

    def executors(allowlist, cancellation):
        engine = ScanEngine(PluginRegistry([plugin]), FixedAllowlist(allowlist), ScanBudget(total_seconds=60),
                            request_timeout_seconds=5, cancellation=cancellation)
        return {ScanType.INTERNAL: EngineScanExecutor(lambda: engine)}

    client = PlatformClient(TestClient(app, base_url=PLATFORM), config.authorization, "test")
    agent = ProbeAgent(client, RemoteReferenceData(client, tmp_path / "ref"), executors,
                       ReportOutbox(tmp_path / "outbox"), wait_seconds=0)
    assert asyncio.run(agent.run_once()) is True

    # 4. Le worker de la plateforme finalise le rapport reçu.
    [(job_id, report)] = reports.reports
    runner = ScanJobRunner(
        repository=SqlScanJobRepository(session_factory),
        executors={ScanType.INTERNAL: StubExecutor()},
        processor_factory=lambda job, profile: FindingProcessor(FindingFilterPolicy(), no_compliance),
        notifier=SpyNotifier(), graph_factory=SpyGraph, ai_trigger=StubAiTrigger(),
    )
    assert runner.finalize(job_id, ScanReport.from_dict(report)) is True

    # Assert
    db.expire_all()
    job = db.get(models.ScanJob, 40)
    titles = [f.title for f in db.query(models.Finding).filter(models.Finding.job_id == 40)]
    assert platform_workers.scans == [], "rien n'est parti vers les workers de la plateforme"
    assert (job.status, job.runs_on, job.probe_id) == ("done", "probe", config.probe_id)
    assert titles == ["Service exposé"]
    assert seen == {"secret": "pw-linux", "kev": [[{"cve": "CVE-2024-6387", "vendorProject": "OpenBSD"}]]}
    assert plugin.targets == ["10.0.0.5"]
    assert "pw-linux" not in config_path.read_text() and not list((tmp_path / "outbox").glob("*.json"))


def test_une_sonde_revoquee_s_arrete_avec_le_code_2(plateforme, tmp_path, monkeypatch):
    app, _ = plateforme
    admin = TestClient(app, base_url=PLATFORM)
    monkeypatch.setattr(cli, "open_http", lambda *args, **kwargs: TestClient(app, base_url=PLATFORM))
    created = admin.post("/probes", json={"workspace_id": CLIENT, "name": "Paris"}).json()
    config_path = tmp_path / "probe.json"
    cli.main(["--config", str(config_path), "enroll", "--platform", PLATFORM, "--token", created["enrollment"]["token"]])

    admin.post(f"/probes/{created['id']}/revoke")

    assert cli.main(["--config", str(config_path), "status"]) == cli.EXIT_REJECTED


def test_un_jeton_d_enrolement_deja_utilise_echoue_sans_ecrire_de_configuration(plateforme, tmp_path, monkeypatch):
    app, _ = plateforme
    admin = TestClient(app, base_url=PLATFORM)
    monkeypatch.setattr(cli, "open_http", lambda *args, **kwargs: TestClient(app, base_url=PLATFORM))
    token = admin.post("/probes", json={"workspace_id": CLIENT, "name": "Paris"}).json()["enrollment"]["token"]
    cli.main(["--config", str(tmp_path / "a.json"), "enroll", "--platform", PLATFORM, "--token", token])

    code = cli.main(["--config", str(tmp_path / "b.json"), "enroll", "--platform", PLATFORM, "--token", token])

    assert code == cli.EXIT_REJECTED
    assert not (tmp_path / "b.json").exists()


def test_l_enrolement_refuse_une_plateforme_en_http_sauf_en_labo(tmp_path):
    code = cli.main(["--config", str(tmp_path / "p.json"), "enroll", "--platform", "http://192.168.2.11:8888",
                     "--token", "x" * 43])

    assert code == cli.EXIT_ERROR
    assert not (tmp_path / "p.json").exists()


def test_la_sonde_lit_l_image_que_la_plateforme_lui_demande(plateforme, tmp_path, monkeypatch, capsys):
    app, _ = plateforme
    admin = TestClient(app, base_url=PLATFORM)
    monkeypatch.setattr(cli, "open_http", lambda *args, **kwargs: TestClient(app, base_url=PLATFORM))
    token = admin.post("/probes", json={"workspace_id": CLIENT, "name": "Paris"}).json()["enrollment"]["token"]
    config_path = str(tmp_path / "probe.json")
    cli.main(["--config", config_path, "enroll", "--platform", PLATFORM, "--token", token])
    image = "ghcr.io/msp/v0cday-probe@sha256:" + "a" * 64
    capsys.readouterr()

    monkeypatch.setattr(settings, "PROBE_IMAGE", image)
    assert cli.main(["--config", config_path, "desired-image"]) == 0
    demandee = capsys.readouterr().out.strip()
    monkeypatch.setattr(settings, "PROBE_IMAGE", "")
    cli.main(["--config", config_path, "desired-image"])
    aucune = capsys.readouterr().out.strip()

    assert (demandee, aucune) == (image, "")
    assert admin.get("/probes").json()["desired_image"] is None


def test_le_jeton_peut_venir_de_l_environnement_pour_ne_pas_paraitre_dans_la_liste_des_processus(
        plateforme, tmp_path, monkeypatch):
    app, _ = plateforme
    admin = TestClient(app, base_url=PLATFORM)
    monkeypatch.setattr(cli, "open_http", lambda *args, **kwargs: TestClient(app, base_url=PLATFORM))
    monkeypatch.setenv("V0CDAY_ENROLL_TOKEN",
                       admin.post("/probes", json={"workspace_id": CLIENT, "name": "Paris"}).json()["enrollment"]["token"])

    code = cli.main(["--config", str(tmp_path / "p.json"), "enroll", "--platform", PLATFORM])

    assert code == 0 and (tmp_path / "p.json").exists()


def test_sans_jeton_l_enrolement_le_dit(tmp_path, monkeypatch):
    monkeypatch.delenv("V0CDAY_ENROLL_TOKEN", raising=False)

    assert cli.main(["--config", str(tmp_path / "p.json"), "enroll", "--platform", PLATFORM]) == cli.EXIT_ERROR
