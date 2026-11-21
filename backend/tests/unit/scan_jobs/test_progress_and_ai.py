import json

import pytest

from app.scan_jobs.ai_trigger import choose_ai_provider
from app.scan_jobs.progress import ThrottledProgressWriter
from tests.fakes import FakeClock


def writer(clock: FakeClock, written: list):
    return ThrottledProgressWriter(lambda doc: written.append(json.loads(doc)["progress"]), monotonic=clock.monotonic, min_interval=2.0)


async def test_les_mises_a_jour_en_cours_trop_rapprochees_sont_ignorees():
    clock, written = FakeClock(), []
    progress = writer(clock, written)

    await progress(0, 4, "a", "A", "running")
    clock.advance(0.5)
    await progress(1, 4, "b", "B", "running")

    assert [p["current_plugin"] for p in written] == ["a"]


async def test_une_fin_de_plugin_est_toujours_ecrite():
    clock, written = FakeClock(), []
    progress = writer(clock, written)

    await progress(0, 4, "a", "A", "running")
    await progress(0, 4, "a", "A", "done")

    assert [p["status"] for p in written] == ["running", "done"]


async def test_le_pourcentage_compte_les_plugins_termines():
    clock, written = FakeClock(), []
    progress = writer(clock, written)

    await progress(1, 4, "b", "B", "running")
    await progress(1, 4, "b", "B", "done")

    assert [p["pct"] for p in written] == [25, 50]


async def test_le_journal_garde_une_ligne_par_plugin_avec_son_dernier_statut():
    clock, written = FakeClock(), []
    progress = writer(clock, written)

    await progress(0, 2, "a", "A", "running")
    clock.advance(3)
    await progress(0, 2, "a", "A", "timeout")

    assert written[-1]["plugins"] == [{"plugin_id": "a", "name": "A", "status": "timeout", "t": 3.0}]


@pytest.mark.parametrize(
    ("configured", "available", "expected"),
    [
        ("gemini", ["claude_cli"], "gemini"),
        ("", ["gemini", "claude_api"], "claude_api"),
        ("", ["custom_llm"], "custom_llm"),
        ("", [], None),
    ],
)
def test_le_fournisseur_ia_configure_prime_sinon_le_prefere_disponible(configured, available, expected):
    assert choose_ai_provider(configured, available) == expected
