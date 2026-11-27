"""
L'agent de la sonde : prendre un job, l'exécuter, rendre compte, sans
jamais perdre un rapport ni scanner hors du périmètre.
"""
import asyncio
import json
import stat

import pytest

from app.probe_agent.agent import ProbeAgent, RemoteCancellation, RemoteProgress, ReportOutbox
from app.probe_agent.cli import probe_executors
from app.probe_agent.platform import JobGone, PlatformUnavailable, ProbeRejected
from app.probe_agent.reference import RemoteReferenceData
from app.scan_jobs.assignment import ScanAssignment, ScanReport
from app.scan_jobs.executors import EngineScanExecutor
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.budget import ScanBudget
from app.scanner.engine import ScanEngine
from app.scanner.plugins.loader import PluginRegistry
from app.scanner.target import ScanType
from tests.fakes import FakePlatform, FakePlugin, StubExecutor, credential, finding, meta


def job(job_id=20, target="10.0.0.5", scan_type="internal", allowlist="10.0.0.0/8", **kwargs):
    return ScanAssignment(job_id=job_id, workspace_id=1, target=target, scan_type=scan_type, allowlist=allowlist, **kwargs)


class Sonde:
    def __init__(self, tmp_path, platform=None, executor=None, local_allowlist=None):
        self.platform = platform or FakePlatform()
        self.executor = executor or StubExecutor(findings=[finding("XSS")])
        self.allowlists = []
        self.sleeps = []
        self.outbox = ReportOutbox(tmp_path / "outbox")

        def executors(allowlist, cancellation):
            self.allowlists.append(str(allowlist))
            return {ScanType.INTERNAL: self.executor, ScanType.EXTERNAL: self.executor}

        async def sleep(seconds):
            self.sleeps.append(seconds)

        self.agent = ProbeAgent(self.platform, RemoteReferenceData(self.platform, tmp_path / "ref"), executors,
                                self.outbox, local_allowlist, wait_seconds=0, sleep=sleep)

    def tour(self):
        return asyncio.run(self.agent.run_once())


# ── Exécution ─────────────────────────────────────────────────────────────────

def test_un_job_est_execute_et_son_rapport_envoye(tmp_path):
    s = Sonde(tmp_path, FakePlatform([job(credentials=(credential(3),))]))

    ran = s.tour()

    assert ran is True
    [report] = s.platform.reports
    assert (report.job_id, [f.title for f in report.findings]) == (20, ["XSS"])
    assert s.executor.received_resources[0].credentials.get(3).secret == "s3cret"
    assert s.outbox.pending() == []


def test_sans_job_l_agent_ne_fait_rien(tmp_path):
    s = Sonde(tmp_path)

    assert s.tour() is False
    assert s.platform.reports == []


def test_le_moteur_recoit_l_allowlist_du_job(tmp_path):
    s = Sonde(tmp_path, FakePlatform([job(allowlist="10.0.0.0/8,.corp.local")]))

    s.tour()

    assert s.allowlists == ["10.0.0.0/8,.corp.local"]


def test_un_job_sans_allowlist_est_refuse_sans_rien_scanner(tmp_path):
    s = Sonde(tmp_path, FakePlatform([job(allowlist=None)]))

    s.tour()

    [report] = s.platform.reports
    assert report.failure.error == "Job without allowlist"
    assert s.executor.received_assignments == []


def test_une_cible_hors_du_perimetre_local_du_client_est_refusee(tmp_path):
    s = Sonde(tmp_path, FakePlatform([job(target="192.168.1.10", allowlist="*")]), local_allowlist="10.0.0.0/8")

    s.tour()

    [report] = s.platform.reports
    assert report.failure.error == "Target outside this probe's scope"
    assert "10.0.0.0/8" in report.failure.detail
    assert s.executor.received_assignments == []


def test_le_perimetre_local_laisse_passer_ce_qu_il_couvre(tmp_path):
    s = Sonde(tmp_path, FakePlatform([job(target="10.1.2.3", allowlist="*")]), local_allowlist="10.0.0.0/8")

    s.tour()

    assert [r.failure for r in s.platform.reports] == [None]


def test_une_cible_hors_de_l_allowlist_du_client_est_bloquee_par_le_moteur_de_la_sonde():
    # Vraie fabrique de production : le moteur n'exécute aucun plugin.
    executors = probe_executors(AllowlistPolicy.from_setting("10.0.0.0/8"), RemoteCancellation(RemoteProgress(None, 20)))
    engine_executor = executors[ScanType.INTERNAL]

    findings = asyncio.run(engine_executor.execute(job(target="192.168.1.10"), None, lambda *_: None))

    assert [f.plugin_id for f in findings] == ["policy.allowlist"]


def test_une_sonde_ne_sait_pas_faire_l_iac_ni_l_inventaire():
    executors = probe_executors(AllowlistPolicy.from_setting("*"), RemoteCancellation(RemoteProgress(None, 1)))

    assert set(executors) == {ScanType.INTERNAL, ScanType.EXTERNAL, ScanType.API}


# ── Progression et arrêt ──────────────────────────────────────────────────────

def test_la_plateforme_peut_arreter_un_scan_en_cours(tmp_path):
    # Arrange : vrai moteur, deux plugins ; la plateforme répond « stop » dès
    # la première progression.
    first, second = FakePlugin(meta("a")), FakePlugin(meta("b", depends_on=["a"]))
    platform = FakePlatform([job()], stop_after_progress=1)

    def executors(allowlist, cancellation):
        engine = ScanEngine(PluginRegistry([first, second]), _Fixed(allowlist), ScanBudget(total_seconds=900),
                            request_timeout_seconds=5, cancellation=cancellation)
        return {ScanType.INTERNAL: EngineScanExecutor(lambda: engine)}

    agent = ProbeAgent(platform, RemoteReferenceData(platform, tmp_path / "ref"), executors,
                       ReportOutbox(tmp_path / "outbox"), wait_seconds=0)

    # Act
    asyncio.run(agent.run_once())

    # Assert
    assert first.was_run and not second.was_run
    [report] = platform.reports
    assert any(f.plugin_id == "system.cancelled" for f in report.findings)
    assert platform.progress_sent[0][0] == 20


class _Fixed:
    def __init__(self, policy):
        self.policy = policy

    def policy_for(self, workspace_id):
        return self.policy


@pytest.mark.parametrize("error", [JobGone("gone"), ProbeRejected("revoked")])
def test_un_job_qui_n_est_plus_a_la_sonde_s_arrete(error):
    platform = FakePlatform()
    platform.fail["progress"] = [error]
    progress = RemoteProgress(platform, 20)

    progress.write(json.dumps({"progress": {}}))

    assert RemoteCancellation(progress).consume(20) is True


def test_une_progression_perdue_n_arrete_pas_le_scan():
    platform = FakePlatform()
    platform.fail["progress"] = [PlatformUnavailable("network")]
    progress = RemoteProgress(platform, 20)

    progress.write(json.dumps({"progress": {}}))

    assert RemoteCancellation(progress).consume(20) is False


# ── Rapports ──────────────────────────────────────────────────────────────────

def test_un_rapport_non_envoye_reste_sur_disque_et_part_au_tour_suivant(tmp_path):
    # Arrange
    s = Sonde(tmp_path, FakePlatform([job()]))
    s.platform.fail["report"] = [PlatformUnavailable("network")]

    # Act / Assert
    with pytest.raises(PlatformUnavailable):
        s.tour()
    assert [r.job_id for r in s.outbox.pending()] == [20]
    s.tour()
    assert [r.job_id for r in s.platform.reports] == [20]
    assert s.outbox.pending() == []


def test_les_rapports_en_attente_ne_sont_lisibles_que_par_la_sonde(tmp_path):
    outbox = ReportOutbox(tmp_path / "outbox")

    outbox.put(ScanReport.succeeded(20, [finding("XSS")]))

    [path] = (tmp_path / "outbox").glob("job-*.json")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_un_rapport_que_la_plateforme_ne_prendra_jamais_est_abandonne(tmp_path):
    s = Sonde(tmp_path, FakePlatform([job()]))
    s.platform.fail["report"] = [JobGone("job failed by the watchdog")]

    s.tour()

    assert s.platform.reports == [] and s.outbox.pending() == []


def test_un_rapport_illisible_est_mis_de_cote(tmp_path):
    (tmp_path / "outbox").mkdir()
    (tmp_path / "outbox" / "job-7.json").write_text("{pas du json")

    assert ReportOutbox(tmp_path / "outbox").pending() == []
    assert (tmp_path / "outbox" / "job-7.unreadable").exists()


# ── Boucle ────────────────────────────────────────────────────────────────────

def test_la_boucle_attend_de_plus_en_plus_quand_la_plateforme_est_injoignable(tmp_path):
    s = Sonde(tmp_path)
    s.platform.fail["next_job"] = [PlatformUnavailable("down")] * 5
    tours = iter(range(6))

    asyncio.run(s.agent.run_forever(lambda: next(tours) >= 6 - 1))

    assert s.sleeps == [5, 10, 30, 60, 60]


def test_la_boucle_s_arrete_quand_la_plateforme_rejette_la_sonde(tmp_path):
    s = Sonde(tmp_path)
    s.platform.fail["next_job"] = [ProbeRejected("revoked")]

    with pytest.raises(ProbeRejected):
        asyncio.run(s.agent.run_forever())


def test_pendant_un_long_scan_la_sonde_reste_vue_en_ligne(tmp_path):
    platform = FakePlatform([job()])
    slow = FakePlugin(meta("slow"), sleep_seconds=0.2)

    def executors(allowlist, cancellation):
        engine = ScanEngine(PluginRegistry([slow]), _Fixed(allowlist), ScanBudget(total_seconds=60),
                            request_timeout_seconds=5, cancellation=cancellation)
        return {ScanType.INTERNAL: EngineScanExecutor(lambda: engine)}

    agent = ProbeAgent(platform, RemoteReferenceData(platform, tmp_path / "ref"), executors,
                       ReportOutbox(tmp_path / "outbox"), wait_seconds=0, keepalive_seconds=0.05)

    asyncio.run(agent.run_once())

    assert platform.heartbeats >= 2


# ── Découverte d'hôtes ────────────────────────────────────────────────────────

from app.discovery.assignment import DiscoveryAssignment, DiscoveryReport  # noqa: E402


def decouverte(network="10.1.2.0/24", allowlist="10.0.0.0/8", budget=3600, discovery_id=7):
    return DiscoveryAssignment(discovery_id=discovery_id, workspace_id=1, network_range=network,
                               allowlist=allowlist, budget_seconds=budget)


class Reseau:
    """discover_hosts de test : une vague par élément de ``vagues``."""

    def __init__(self, vagues, plante=None):
        self.vagues = vagues
        self.plante = plante
        self.reseaux = []

    def __call__(self, net, on_progress, should_stop):
        self.reseaux.append(str(net))
        trouves = []
        for i, vague in enumerate(self.vagues):
            if should_stop():
                break
            trouves += vague
            on_progress((i + 1) * 128, list(trouves))
        if self.plante:
            raise self.plante
        return trouves


def sonde_qui_decouvre(tmp_path, platform, reseau, local_allowlist=None, horloge=None):
    agent = ProbeAgent(platform, RemoteReferenceData(platform, tmp_path / "ref"), lambda a, c: {},
                       ReportOutbox(tmp_path / "outbox"), local_allowlist, wait_seconds=0,
                       discover=reseau, clock=horloge or (lambda: 0.0))
    asyncio.run(agent.run_once())
    return agent


H1, H2 = {"ip": "10.1.2.7", "hostname": "nas.lan"}, {"ip": "10.1.2.40", "hostname": None}


def test_une_decouverte_envoie_ses_hotes_vague_par_vague_puis_son_rapport(tmp_path):
    platform = FakePlatform([decouverte()])
    reseau = Reseau([[H1], [H2]])

    sonde_qui_decouvre(tmp_path, platform, reseau)

    assert reseau.reseaux == ["10.1.2.0/24"]
    assert platform.progress_sent == [(7, {"probed": 128, "hosts": [H1]}), (7, {"probed": 256, "hosts": [H1, H2]})]
    [rapport] = platform.reports
    assert rapport == DiscoveryReport(7, "done", 256, [H1, H2])
    assert ReportOutbox(tmp_path / "outbox").pending() == []


@pytest.mark.parametrize("assignment, local, raison", [
    (decouverte(allowlist=None), None, "no allowlist"),
    (decouverte(network="10.0.0.0/8", allowlist="10.1.0.0/16"), None, "outside the client's allowlist"),
    (decouverte(network="10.1.2.0/24"), "10.9.0.0/16", "outside the scope the client set on its probe"),
    (decouverte(network="8.8.8.0/24", allowlist=""), None, "Refused range"),
])
def test_une_decouverte_hors_perimetre_est_refusee_sans_rien_sonder(tmp_path, assignment, local, raison):
    platform = FakePlatform([assignment])
    reseau = Reseau([[H1]])

    sonde_qui_decouvre(tmp_path, platform, reseau, local_allowlist=local)

    assert reseau.reseaux == []
    [rapport] = platform.reports
    assert rapport.status == "failed" and raison in rapport.error


def test_la_plateforme_peut_arreter_une_decouverte_en_gardant_ses_hotes(tmp_path):
    platform = FakePlatform([decouverte()], stop_after_progress=1)

    sonde_qui_decouvre(tmp_path, platform, Reseau([[H1], [H2]]))

    [rapport] = platform.reports
    assert (rapport.status, rapport.hosts) == ("cancelled", [H1])


def test_le_budget_de_temps_arrete_une_decouverte(tmp_path):
    temps = iter([0.0, 0.0, 120.0])
    platform = FakePlatform([decouverte(budget=60)])

    sonde_qui_decouvre(tmp_path, platform, Reseau([[H1], [H2]]), horloge=lambda: next(temps))

    [rapport] = platform.reports
    assert rapport.status == "failed" and "time budget (1 min)" in rapport.error
    assert rapport.hosts == [H1]


def test_une_decouverte_qui_plante_est_rapportee_avec_ses_hotes(tmp_path):
    platform = FakePlatform([decouverte()])

    sonde_qui_decouvre(tmp_path, platform, Reseau([[H1]], plante=OSError("too many open files")))

    [rapport] = platform.reports
    assert rapport.status == "failed" and "too many open files" in rapport.error
    assert rapport.hosts == [H1]


def test_une_progression_de_decouverte_perdue_ne_l_arrete_pas(tmp_path):
    platform = FakePlatform([decouverte()])
    platform.fail["discovery_progress"] = [PlatformUnavailable("réseau coupé")]

    sonde_qui_decouvre(tmp_path, platform, Reseau([[H1], [H2]]))

    assert platform.reports[0].status == "done"


def test_un_rapport_de_decouverte_non_envoye_reste_sur_disque(tmp_path):
    platform = FakePlatform([decouverte()])
    platform.fail["discovery_report"] = [PlatformUnavailable("réseau coupé")]

    with pytest.raises(PlatformUnavailable):
        sonde_qui_decouvre(tmp_path, platform, Reseau([[H1]]))

    [en_attente] = ReportOutbox(tmp_path / "outbox").pending()
    assert en_attente == DiscoveryReport(7, "done", 128, [H1])
    assert (tmp_path / "outbox" / "discovery-7.json").exists()
