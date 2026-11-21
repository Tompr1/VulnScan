from datetime import datetime, timedelta, timezone

import pytest

from app.inventory.scheduling import is_due
from app.scan_jobs.executors import InventoryScanExecutor
from app.scan_jobs.repository import ScanJobSnapshot
from app.scanner.profile import ScanProfile

NOW = datetime(2026, 11, 21, 6, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("frequency", "last", "due"),
    [
        ("daily", None, True),
        ("daily", NOW - timedelta(hours=23), False),
        ("daily", NOW - timedelta(hours=24), True),
        ("weekly", NOW - timedelta(days=6), False),
        ("weekly", NOW - timedelta(days=7), True),
        ("manual", None, False),
        ("hourly", None, False),
    ],
)
def test_une_connexion_est_synchronisee_selon_sa_frequence(frequency, last, due):
    assert is_due(frequency, last, NOW) is due


class SpyCollector:
    def __init__(self):
        self.calls = []

    def collect(self, connection_id, workspace_id):
        self.calls.append((connection_id, workspace_id))


def job(meta):
    return ScanJobSnapshot(id=9, workspace_id=1, target="intune:Tenant", scan_type="inventory", profile_id=None, meta=meta)


async def test_un_job_d_inventaire_collecte_la_connexion_qu_il_designe():
    collector, events = SpyCollector(), []

    async def progress(*args):
        events.append(args[-1])

    findings = await InventoryScanExecutor(lambda: collector).execute(job({"inventory_connection_id": 3}), ScanProfile(), progress)

    assert collector.calls == [(3, 1)]
    assert findings == []
    assert events == ["running", "done"]


async def test_un_job_d_inventaire_sans_connexion_est_refuse():
    async def progress(*_):
        return None

    with pytest.raises(ValueError, match="inventory connection"):
        await InventoryScanExecutor(SpyCollector).execute(job({}), ScanProfile(), progress)


def test_un_job_d_inventaire_n_a_pas_besoin_de_profil():
    assert InventoryScanExecutor(SpyCollector).requires_profile is False
