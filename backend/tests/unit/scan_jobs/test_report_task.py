"""Tâche de worker qui finalise le rapport envoyé par une sonde."""
from app import worker_tasks
from app.scan_jobs.assignment import ScanReport
from tests.fakes import finding


class SpyRunner:
    def __init__(self):
        self.finalized = []

    def finalize(self, job_id, report):
        self.finalized.append((job_id, report))
        return True


def test_le_rapport_recu_est_finalise_par_le_runner(monkeypatch):
    runner = SpyRunner()
    monkeypatch.setattr(worker_tasks, "build_scan_job_runner", lambda: runner)
    report = ScanReport.succeeded(20, [finding("XSS")])

    worker_tasks.finalize_scan_report(20, report.to_dict())

    assert runner.finalized == [(20, report)]


def test_un_rapport_illisible_est_ignore_sans_planter_le_worker(monkeypatch):
    runner = SpyRunner()
    monkeypatch.setattr(worker_tasks, "build_scan_job_runner", lambda: runner)

    worker_tasks.finalize_scan_report(20, {"findings": "pas une liste"})

    assert runner.finalized == []
