import asyncio
import json
from datetime import timedelta

import pytest

from app.scan_jobs.filtering import FindingFilterPolicy
from app.scan_jobs.processing import FindingProcessor
from app.scan_jobs.assignment import ScanAssignment, ScanReport, assign
from app.scan_jobs.execution import ScanExecution
from app.scan_jobs.outcome import JobFailure
from app.scan_jobs.repository import ScanJobSnapshot
from app.scan_jobs.runner import ScanJobRunner
from app.scanner.profile import WEB_AUTH_PLUGIN_ID, ScanProfile
from app.scanner.resources import InMemoryCredentialVault
from app.scanner.target import ScanType
from tests.fakes import (
    FakeClock,
    InMemoryScanJobRepository,
    SpyGraph,
    SpyNotifier,
    StubAiTrigger,
    StubExecutor,
    credential,
    finding,
    no_compliance,
)

WS = 1


class Harness:
    """Runner wired to fakes, with handles on every collaborator."""

    def __init__(self, executor=None, ai_trigger=None, processor_factory=None, vault=None):
        self.clock = FakeClock()
        self.vault_requests = []
        vault = vault or InMemoryCredentialVault()
        self.repository = InMemoryScanJobRepository()
        self.executor = executor or StubExecutor(findings=[finding("XSS", severity="high")])
        self.notifier = SpyNotifier()
        self.graph = SpyGraph()
        self.ai_trigger = ai_trigger or StubAiTrigger()
        self.runner = ScanJobRunner(
            repository=self.repository,
            executors={ScanType.INTERNAL: self.executor, ScanType.API: self.executor},
            processor_factory=processor_factory or (lambda job, profile: FindingProcessor(FindingFilterPolicy(), no_compliance)),
            notifier=self.notifier,
            graph_factory=lambda: self.graph,
            ai_trigger=self.ai_trigger,
            clock=self.clock.utc_now,
            credentials=lambda workspace_id: self.vault_requests.append(workspace_id) or vault,
        )

    def add_job(self, job_id=10, scan_type="internal", profile_id=5, meta=None, with_profile=True):
        snapshot = ScanJobSnapshot(
            id=job_id, workspace_id=WS, target="10.0.0.5", scan_type=scan_type, profile_id=profile_id,
            meta=meta or {}, created_at=self.clock.utc - timedelta(seconds=30),
        )
        self.repository.add_job(snapshot)
        if with_profile:
            self.repository.add_profile(WS, profile_id, ScanProfile())
        return snapshot


def test_un_scan_reussi_enregistre_les_constats_et_termine_le_job():
    # Arrange
    h = Harness()
    h.add_job()

    # Act
    h.runner.run(10)

    # Assert
    stored = h.repository.jobs[10]
    assert stored.status == "done"
    assert [f.title for f in h.repository.saved[10]] == ["XSS"]
    assert stored.completion.findings_saved == 1
    assert stored.progress, "progress was written while scanning"


def test_un_scan_reussi_notifie_les_integrations_avec_un_resume():
    h = Harness()
    h.add_job()

    h.runner.run(10)

    workspace, summary = h.notifier.completed[0]
    assert (workspace, summary.job_id, summary.saved_count, summary.risk_level) == (WS, 10, 1, "HIGH")
    assert summary.duration_seconds == 30


def test_les_constats_enregistres_sont_publies_dans_le_graphe_d_attaque():
    h = Harness()
    h.add_job()

    h.runner.run(10)

    assert [f.title for f in h.graph.recorded] == ["XSS"]
    assert h.graph.closed


def test_le_job_passe_en_analyse_quand_une_analyse_ia_est_lancee():
    h = Harness(ai_trigger=StubAiTrigger(queues=True))
    h.add_job()

    h.runner.run(10)

    assert h.repository.status_of(10) == "analyzing"
    assert h.ai_trigger.calls == [(10, WS, 1)]


def test_l_analyse_ia_automatique_n_est_pas_proposee_pour_un_type_de_scan_qui_l_exclut():
    # Inventory audits name users and devices: they never go to an AI provider automatically.
    h = Harness(executor=StubExecutor(findings=[finding("Outdated OS")], ai_analysis=False), ai_trigger=StubAiTrigger(queues=True))
    h.add_job()

    h.runner.run(10)

    assert h.ai_trigger.calls == []
    assert h.repository.status_of(10) == "done"


def test_un_echec_de_lancement_de_l_analyse_ia_ne_fait_pas_echouer_le_scan():
    h = Harness(ai_trigger=StubAiTrigger(error=RuntimeError("redis down")))
    h.add_job()

    h.runner.run(10)

    assert h.repository.status_of(10) == "done"


def test_un_job_inconnu_est_ignore():
    h = Harness()

    h.runner.run(999)

    assert h.notifier.completed == h.notifier.failed == []


def test_un_job_dont_le_profil_a_disparu_echoue_en_erreur_de_configuration():
    h = Harness()
    h.add_job(with_profile=False)

    h.runner.run(10)

    stored = h.repository.jobs[10]
    assert (stored.status, stored.failure.error, stored.failure.error_type) == ("failed", "Profile not found", "configuration")
    assert stored.started_at is None, "a misconfigured job never starts"
    assert h.notifier.failed[0][1].error_type == "configuration"


def test_un_scan_api_n_a_pas_besoin_de_profil():
    h = Harness(executor=StubExecutor(requires_profile=False))
    h.add_job(scan_type="api", profile_id=None, with_profile=False)

    h.runner.run(10)

    assert h.repository.status_of(10) == "done"


def test_un_type_de_scan_inconnu_fait_echouer_le_job():
    h = Harness()
    h.add_job(scan_type="quantum")

    h.runner.run(10)

    assert h.repository.jobs[10].failure.error == "Unknown scan type: quantum"


def test_une_erreur_du_moteur_de_scan_est_enregistree_avec_sa_trace():
    h = Harness(executor=StubExecutor(error=ConnectionError("host unreachable")))
    h.add_job()

    h.runner.run(10)

    failure = h.repository.jobs[10].failure
    assert (failure.error, failure.error_type) == ("host unreachable", "scan_engine")
    assert "ConnectionError" in failure.traceback
    assert 10 not in h.repository.saved


def test_une_erreur_inattendue_apres_le_scan_fait_echouer_le_job_proprement():
    def broken_factory(job, profile):
        raise KeyError("compliance dataset")

    h = Harness(processor_factory=broken_factory)
    h.add_job()

    h.runner.run(10)

    assert h.repository.jobs[10].failure.error_type == "unhandled"


def test_si_l_echec_ne_peut_pas_etre_enregistre_le_worker_ne_plante_pas():
    h = Harness(executor=StubExecutor(error=RuntimeError("boom")))
    h.add_job()
    h.repository.fail_on_mark_failed = True

    h.runner.run(10)

    assert h.notifier.failed == []


def test_l_authentification_web_du_job_est_transmise_au_scan():
    h = Harness()
    h.add_job(meta={"web_auth": {"type": "bearer", "credential_id": 3}})

    h.runner.run(10)

    profile = h.executor.received_profiles[0]
    assert profile.plugin_selection[WEB_AUTH_PLUGIN_ID] is True
    assert profile.options["web_auth"]["credential_id"] == 3


@pytest.mark.parametrize("executor", [StubExecutor(), StubExecutor(error=RuntimeError("boom"))])
def test_les_identifiants_ephemeres_sont_nettoyes_quelle_que_soit_l_issue(executor):
    h = Harness(executor=executor)
    h.add_job()

    h.runner.run(10)

    assert h.repository.deleted_credentials_for == [10]


def test_un_job_ne_reference_un_identifiant_ephemere_que_s_il_est_marque_comme_tel():
    marked = ScanJobSnapshot(1, WS, "t", "internal", 1, {"web_auth": {"type": "form", "credential_id": "8"}, "web_auth_credential_ephemeral": True})
    unmarked = ScanJobSnapshot(1, WS, "t", "internal", 1, {"web_auth": {"type": "form", "credential_id": 8}})

    assert (marked.ephemeral_credential_id, unmarked.ephemeral_credential_id) == (8, None)


class SpyAnnouncer:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def announce(self, job, findings, summary):
        self.calls.append((job.id, [f.title for f in findings], summary.saved_count))
        if self.error:
            raise self.error


def runner_with_announcer(announcer):
    h = Harness()
    h.runner = ScanJobRunner(
        repository=h.repository,
        executors={ScanType.INTERNAL: h.executor},
        processor_factory=lambda job, profile: FindingProcessor(FindingFilterPolicy(), no_compliance),
        notifier=h.notifier,
        graph_factory=lambda: h.graph,
        ai_trigger=h.ai_trigger,
        clock=h.clock.utc_now,
        announcers={ScanType.INTERNAL: announcer},
    )
    h.add_job()
    return h


def test_un_type_de_scan_avec_son_annonceur_remplace_la_notification_de_fin():
    announcer = SpyAnnouncer()
    h = runner_with_announcer(announcer)

    h.runner.run(10)

    assert announcer.calls == [(10, ["XSS"], 1)]
    assert h.notifier.completed == []


def test_un_echec_d_annonce_ne_fait_pas_echouer_le_job():
    h = runner_with_announcer(SpyAnnouncer(error=RuntimeError("Slack down")))

    h.runner.run(10)

    assert h.repository.status_of(10) == "done"


# ── Identifiants transmis à l'exécution ───────────────────────────────────────

def test_l_execution_recoit_les_identifiants_du_client_que_nomme_le_profil():
    # Arrange
    h = Harness(vault=InMemoryCredentialVault([credential(3), credential(4)]))
    h.add_job(with_profile=False)
    h.repository.add_profile(WS, 5, ScanProfile(options={"auth": {"ssh_credential_id": 3}}))

    # Act
    h.runner.run(10)

    # Assert
    assignment = h.executor.received_assignments[0]
    assert h.vault_requests == [WS]
    assert [c.id for c in assignment.credentials] == [3]
    assert h.executor.received_resources[0].credentials.get(3).secret == "s3cret"


def test_un_job_passe_par_le_traitement_avant_d_etre_termine():
    statuses = []
    h = Harness()
    h.add_job()
    save = h.repository.save_findings
    h.repository.save_findings = lambda job, findings: (statuses.append(h.repository.status_of(job.id)), save(job, findings))

    h.runner.run(10)

    assert (statuses, h.repository.status_of(10)) == (["processing"], "done")


# ── Rapport produit ailleurs (sonde) ──────────────────────────────────────────

async def no_progress(*_):
    return None


def harness_with_running_job(**kwargs):
    h = Harness(**kwargs)
    h.add_job()
    h.repository.mark_running(10, h.clock.utc)
    return h


def test_un_rapport_recu_pour_un_job_en_cours_le_termine():
    h = harness_with_running_job()

    accepted = h.runner.finalize(10, ScanReport.succeeded(10, [finding("XSS", severity="high")]))

    assert accepted is True
    assert h.repository.status_of(10) == "done"
    assert [f.title for f in h.repository.saved[10]] == ["XSS"]
    assert h.notifier.completed[0][1].saved_count == 1


def test_un_rapport_recu_deux_fois_n_est_enregistre_qu_une_fois():
    h = harness_with_running_job()
    report = ScanReport.succeeded(10, [finding("XSS")])

    results = (h.runner.finalize(10, report), h.runner.finalize(10, report))

    assert results == (True, False)
    assert len(h.repository.saved[10]) == 1
    assert len(h.notifier.completed) == 1


def test_un_rapport_d_echec_fait_echouer_le_job():
    h = harness_with_running_job()

    h.runner.finalize(10, ScanReport.failed(10, JobFailure("host unreachable", "scan_engine")))

    stored = h.repository.jobs[10]
    assert (stored.status, stored.failure.error) == ("failed", "host unreachable")
    assert h.notifier.failed[0][1].error_type == "scan_engine"


def test_un_rapport_pour_un_job_que_le_watchdog_a_deja_clos_est_ignore():
    h = harness_with_running_job()
    h.repository.jobs[10].status = "failed"

    accepted = h.runner.finalize(10, ScanReport.succeeded(10, [finding("XSS")]))

    assert accepted is False
    assert 10 not in h.repository.saved
    assert h.repository.status_of(10) == "failed"


def test_un_rapport_d_un_autre_job_est_refuse():
    h = harness_with_running_job()

    assert h.runner.finalize(10, ScanReport.succeeded(11, [finding("XSS")])) is False
    assert h.repository.status_of(10) == "running"


def test_un_rapport_pour_un_job_inconnu_est_refuse():
    assert Harness().runner.finalize(999, ScanReport.succeeded(999, [])) is False


def test_les_constats_d_un_job_dont_le_profil_a_disparu_pendant_le_scan_sont_gardes():
    h = Harness()
    h.add_job(with_profile=False)
    h.repository.mark_running(10, h.clock.utc)

    h.runner.finalize(10, ScanReport.succeeded(10, [finding("XSS")]))

    assert h.repository.status_of(10) == "done"
    assert [f.title for f in h.repository.saved[10]] == ["XSS"]


def test_un_rapport_venu_d_ailleurs_nettoie_les_identifiants_ephemeres():
    h = harness_with_running_job()

    h.runner.finalize(10, ScanReport.succeeded(10, []))

    assert h.repository.deleted_credentials_for == [10]


def test_un_job_execute_ailleurs_aboutit_au_meme_resultat_qu_en_local():
    # Arrange : deux plateformes identiques ; la seconde fait exécuter le job
    # « ailleurs », en ne passant que du JSON, comme avec une sonde.
    findings = [finding("XSS", severity="high"), finding("Banner")]
    profile = ScanProfile(options={"auth": {"ssh_credential_id": 3}})
    vault = InMemoryCredentialVault([credential(3)])
    local, remote = Harness(StubExecutor(findings), vault=vault), Harness(StubExecutor(findings), vault=vault)
    for h in (local, remote):
        h.add_job(with_profile=False)
        h.repository.add_profile(WS, 5, profile)

    # Act
    local.runner.run(10)
    job = remote.repository.load_job(10)
    sent = json.dumps(assign(job.id, job.workspace_id, job.target, job.scan_type, profile, job.meta, vault).to_dict())
    remote.repository.mark_running(10, remote.clock.utc)
    probe = ScanExecution({ScanType.INTERNAL: StubExecutor(findings)})
    report = asyncio.run(probe.execute(ScanAssignment.from_dict(json.loads(sent)), no_progress))
    remote.runner.finalize(10, ScanReport.from_dict(json.loads(json.dumps(report.to_dict()))))

    # Assert
    def outcome(h):
        return h.repository.status_of(10), [(f.title, f.severity, f.risk_score) for f in h.repository.saved[10]]

    assert outcome(remote) == outcome(local)
