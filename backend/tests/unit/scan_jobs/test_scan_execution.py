"""
L'exécution d'une affectation, sans base de données : c'est la moitié d'un
job qui tournera sur la sonde.
"""
import asyncio

from app.scan_jobs.assignment import ScanAssignment
from app.scan_jobs.execution import ScanExecution
from app.scanner.resources import InMemoryReferenceData
from app.scanner.target import ScanType
from tests.fakes import StubExecutor, credential, finding

ASSIGNMENT = ScanAssignment(job_id=10, workspace_id=1, target="10.0.0.5", scan_type="internal",
                            credentials=(credential(3),))


async def no_progress(*_):
    return None


def execute(execution, assignment=ASSIGNMENT):
    return asyncio.run(execution.execute(assignment, no_progress))


def test_une_execution_reussie_rend_les_constats_bruts():
    executor = StubExecutor(findings=[finding("XSS")])

    report = execute(ScanExecution({ScanType.INTERNAL: executor}))

    assert (report.job_id, [f.title for f in report.findings], report.failure) == (10, ["XSS"], None)


def test_l_executeur_recoit_les_identifiants_de_l_affectation_et_les_donnees_de_reference():
    # Arrange
    executor = StubExecutor()
    reference = InMemoryReferenceData({"cisa_kev": [[{"cve": "CVE-2024-1"}]]})

    # Act
    execute(ScanExecution({ScanType.INTERNAL: executor}, reference))

    # Assert
    resources = executor.received_resources[0]
    assert resources.credentials.get(3).secret == "s3cret"
    assert resources.reference is reference


def test_un_type_de_scan_que_l_execution_ne_sait_pas_faire_rend_un_echec_de_configuration():
    report = execute(ScanExecution({}))

    assert (report.failure.error, report.failure.error_type) == ("Unknown scan type: internal", "configuration")


def test_une_erreur_de_l_executeur_rend_un_echec_avec_sa_trace():
    executor = StubExecutor(error=ConnectionError("host unreachable"))

    report = execute(ScanExecution({ScanType.INTERNAL: executor}))

    assert (report.failure.error, report.failure.error_type) == ("host unreachable", "scan_engine")
    assert "ConnectionError" in report.failure.traceback
    assert report.findings == ()
