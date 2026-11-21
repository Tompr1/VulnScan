import pytest

from app.scanner.allowlist import AllowlistPolicy
from app.scanner.budget import ScanBudget
from app.scanner.engine import ScanEngine
from app.scanner.plugins.loader import PluginRegistry
from app.scanner.profile import ScanProfile
from app.scanner.target import InvalidTargetError, ScanType
from tests.fakes import FakeClock, FakePlugin, SpyCancellationSignal, finding, meta

TARGET = "http://10.0.0.5"


def make_engine(*plugins, allowlist="", clock=None, cancellation=None, budget=None) -> ScanEngine:
    return ScanEngine(
        registry=PluginRegistry(plugins),
        allowlist=AllowlistPolicy.from_setting(allowlist),
        budget=budget or ScanBudget(total_seconds=900, kill_grace_seconds=0),
        request_timeout_seconds=5,
        cancellation=cancellation,
        monotonic=(clock or FakeClock()).monotonic,
    )


async def scan(engine: ScanEngine, target: str = TARGET, **kwargs):
    return await engine.scan(target, ScanProfile(), workspace_id=1, **kwargs)


async def test_les_plugins_sont_executes_contre_l_hote_de_la_cible():
    plugin = FakePlugin(meta("p"))

    await scan(make_engine(plugin))

    assert plugin.targets == ["10.0.0.5"]


async def test_un_plugin_lit_les_artefacts_publies_par_ses_dependances():
    # Arrange
    seen = {}
    producer = FakePlugin(meta("producer", provides=["net.open_ports"]), artifacts={"net.open_ports": [80, 443]})
    consumer = FakePlugin(
        meta("consumer", depends_on=["producer"]),
        on_run=lambda ctx: seen.update(ports=ctx.get("net.open_ports")),
    )

    # Act
    await scan(make_engine(consumer, producer))

    # Assert
    assert seen["ports"] == [80, 443]


async def test_le_contexte_expose_la_cible_et_les_options_du_profil():
    plugin = FakePlugin(meta("p"))

    await make_engine(plugin).scan(TARGET, ScanProfile(options={"depth": 2}), workspace_id=7)

    ctx = plugin.contexts[0]
    assert (ctx.get("workspace_id"), ctx.get("target_host"), ctx.get("target_scheme")) == (7, "10.0.0.5", "http")
    assert ctx.get("profile_options") == {"depth": 2}


async def test_les_constats_en_double_ne_sont_rapportes_qu_une_fois():
    duplicate = finding("Same", fingerprint="fp-1")
    engine = make_engine(FakePlugin(meta("a"), findings=[duplicate]), FakePlugin(meta("b"), findings=[finding("Same", fingerprint="fp-1")]))

    findings = await scan(engine)

    assert [f.fingerprint for f in findings] == ["fp-1"]


async def test_un_constat_sans_empreinte_en_recoit_une_stable():
    engine = make_engine(FakePlugin(meta("p"), findings=[finding("No fp", fingerprint="")]))

    first = (await scan(engine))[0].fingerprint
    second = (await scan(make_engine(FakePlugin(meta("p"), findings=[finding("No fp", fingerprint="")]))))[0].fingerprint

    assert first and first == second


async def test_un_plugin_qui_plante_n_interrompt_pas_le_scan():
    # Arrange
    broken = FakePlugin(meta("broken", provides=["infra.count"], artifact_defaults={"infra.count": 0}), error=RuntimeError("boom"))
    seen = {}
    after = FakePlugin(meta("after", soft_depends_on=["broken"]), on_run=lambda ctx: seen.update(count=ctx.get("infra.count")))

    # Act
    findings = await scan(make_engine(broken, after))

    # Assert
    assert after.was_run
    assert seen["count"] == 0, "downstream plugins get the declared fallback artifact"
    error = next(f for f in findings if f.plugin_id == "broken")
    assert error.title == "Plugin error: Broken"
    assert error.evidence == "boom"


async def test_un_plugin_trop_lent_est_interrompu_et_signale():
    slow = FakePlugin(meta("slow", timeout_seconds=0.01), sleep_seconds=1)

    findings = await scan(make_engine(slow))

    assert findings[0].title == "Plugin timed out: Slow"
    assert findings[0].severity == "info"


async def test_les_plugins_restants_sont_sautes_quand_le_budget_est_epuise():
    # Arrange: the first plugin "takes" 70s of a 100s budget (30s reserve).
    clock = FakeClock()
    first = FakePlugin(meta("first"), on_run=lambda ctx: clock.advance(70))
    second = FakePlugin(meta("second", depends_on=["first"]))
    engine = make_engine(first, second, clock=clock, budget=ScanBudget(total_seconds=100, reserve_seconds=30))

    # Act
    findings = await scan(engine)

    # Assert
    assert not second.was_run
    assert [f.title for f in findings] == ["Plugin skipped (scan budget exhausted): Second"]


async def test_un_scan_annule_s_arrete_avant_le_plugin_suivant():
    plugin = FakePlugin(meta("p"))
    engine = make_engine(plugin, cancellation=SpyCancellationSignal(cancelled_jobs={42}))

    findings = await scan(engine, job_id=42)

    assert not plugin.was_run
    assert findings[0].plugin_id == "system.cancelled"


async def test_l_annulation_d_un_autre_job_n_arrete_pas_le_scan():
    plugin = FakePlugin(meta("p"))

    await scan(make_engine(plugin, cancellation=SpyCancellationSignal(cancelled_jobs={1})), job_id=2)

    assert plugin.was_run


async def test_une_cible_interne_hors_allowlist_n_est_pas_scannee():
    plugin = FakePlugin(meta("p"))

    findings = await scan(make_engine(plugin, allowlist="10.0.0.0/8"), target="192.168.1.1")

    assert not plugin.was_run
    assert [f.plugin_id for f in findings] == ["policy.allowlist"]
    assert findings[0].evidence == "ALLOWLIST=10.0.0.0/8"


async def test_une_cible_externe_est_scannee_meme_hors_allowlist():
    plugin = FakePlugin(meta("p"))

    await scan(make_engine(plugin, allowlist="10.0.0.0/8"), target="https://example.org", scan_type=ScanType.EXTERNAL)

    assert plugin.was_run


async def test_une_cible_sans_hote_est_refusee_avant_tout_scan():
    with pytest.raises(InvalidTargetError):
        await scan(make_engine(FakePlugin(meta("p"))), target="http://")


async def test_la_progression_est_signalee_au_debut_et_a_la_fin_de_chaque_plugin():
    events = []

    await scan(make_engine(FakePlugin(meta("p"))), progress_callback=lambda *args: events.append(args))

    assert events == [(0, 1, "p", "P", "running"), (0, 1, "p", "P", "done")]


async def test_une_erreur_du_suivi_de_progression_n_interrompt_pas_le_scan():
    def broken_progress(*_):
        raise RuntimeError("UI down")

    findings = await scan(make_engine(FakePlugin(meta("p"), findings=[finding("Kept")])), progress_callback=broken_progress)

    assert [f.title for f in findings] == ["Kept"]


async def test_les_constats_sont_enrichis_avec_le_contexte_de_la_cible():
    engine = make_engine(FakePlugin(meta("p"), findings=[finding("Old nginx", severity="high", evidence="version=1.18.0")]))

    result = (await scan(engine))[0]

    assert f"Target: {TARGET} (scan type: internal)" in result.description
    assert "[AFFECTED VERSION] Detected version: 1.18.0." in result.remediation
