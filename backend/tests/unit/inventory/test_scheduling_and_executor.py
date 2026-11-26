from datetime import datetime, timedelta, timezone

import pytest

from app.inventory.scheduling import is_due
from app.scan_jobs.executors import InventoryScanExecutor
from app.scan_jobs.assignment import ScanAssignment
from app.scanner.plugins.base import Finding
from app.scanner.resources import ScanResources
from app.scanner.target import ScanType

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
    def __init__(self, calls=None):
        self.calls = calls if calls is not None else []

    def collect(self, connection_id, workspace_id):
        self.calls.append(("collect", connection_id, workspace_id))


class StubAudit:
    def __init__(self, calls, findings=()):
        self.calls = calls
        self.findings = list(findings)

    def run(self, connection_id, workspace_id, job_id):
        self.calls.append(("audit", connection_id, workspace_id, job_id))
        return self.findings


def job(meta):
    return ScanAssignment(job_id=9, workspace_id=1, target="intune:Tenant", scan_type="inventory", meta=meta)


def executor(calls, findings=()):
    return InventoryScanExecutor(lambda: SpyCollector(calls), lambda: StubAudit(calls, findings))


async def test_un_job_d_inventaire_collecte_puis_audite_la_connexion_qu_il_designe():
    calls, events = [], []
    issue = Finding("inventory.os_unsupported", "Windows 11 23H2 (W) is no longer supported — PC-04", device_id=7)

    async def progress(*args):
        events.append((args[2], args[-1]))

    findings = await executor(calls, [issue]).execute(job({"inventory_connection_id": 3}), ScanResources.none(), progress)

    assert calls == [("collect", 3, 1), ("audit", 3, 1, 9)]
    assert findings == [issue]
    assert events == [
        ("inventory.collect", "running"), ("inventory.collect", "done"),
        ("inventory.audit", "running"), ("inventory.audit", "done"),
    ]


async def test_un_job_d_inventaire_sans_connexion_est_refuse():
    calls = []

    async def progress(*_):
        return None

    with pytest.raises(ValueError, match="inventory connection"):
        await executor(calls).execute(job({}), ScanResources.none(), progress)
    assert calls == []


def test_un_job_d_inventaire_n_a_pas_besoin_de_profil_ni_d_analyse_ia():
    inventory = executor([])

    assert (ScanType.INVENTORY.requires_profile, inventory.ai_analysis) == (False, False)
