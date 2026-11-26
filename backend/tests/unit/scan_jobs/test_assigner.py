"""Préparation d'un job pour son exécuteur, sur la plateforme ou une sonde."""
import pytest

from app.scan_jobs.assigner import JobAssigner, JobNotReady
from app.scan_jobs.repository import ScanJobSnapshot
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.profile import ScanProfile
from app.scanner.resources import InMemoryCredentialVault
from tests.fakes import InMemoryScanJobRepository, credential


class Allowlists:
    def __init__(self, setting):
        self.setting = setting

    def policy_for(self, workspace_id):
        return AllowlistPolicy.from_setting(self.setting)


def job(scan_type="internal", profile_id=5, meta=None):
    return ScanJobSnapshot(10, 1, "10.0.0.5", scan_type, profile_id, meta or {})


def assigner(profile=None, allowlist=None, vault=None):
    repository = InMemoryScanJobRepository()
    if profile is not None:
        repository.add_profile(1, 5, profile)
    return JobAssigner(repository, lambda ws: vault or InMemoryCredentialVault(),
                       Allowlists(allowlist) if allowlist is not None else None)


def test_un_scan_reseau_prend_le_profil_qu_il_nomme_avec_l_authentification_web_du_job():
    profile = assigner(ScanProfile({"p": True})).profile_for(job(meta={"web_auth": {"type": "bearer", "credential_id": 3}}))

    assert profile.plugin_selection == {"p": True, "web.auth": True}


def test_un_scan_api_n_a_pas_besoin_de_profil():
    assert assigner().profile_for(job("api", profile_id=None)) == ScanProfile()


@pytest.mark.parametrize(("scan_type", "error"), [("internal", "Profile not found"), ("quantum", "Unknown scan type: quantum")])
def test_un_job_qui_ne_peut_pas_tourner_le_dit(scan_type, error):
    with pytest.raises(JobNotReady) as raised:
        assigner().profile_for(job(scan_type))

    assert (raised.value.failure.error, raised.value.failure.error_type) == (error, "configuration")


@pytest.mark.parametrize(("setting", "attendu"), [("10.0.0.0/8,.corp.local", "10.0.0.0/8,.corp.local"), ("*", "*"), ("", "*")])
def test_l_affectation_porte_l_allowlist_du_client_sous_la_forme_du_reglage(setting, attendu):
    a = assigner(ScanProfile(), allowlist=setting).assignment_for(job(), ScanProfile())

    assert a.allowlist == attendu
    assert str(AllowlistPolicy.from_setting(a.allowlist)) == attendu, "la sonde relit la même politique"


def test_sur_la_plateforme_l_affectation_ne_porte_pas_d_allowlist():
    assert assigner(ScanProfile()).assignment_for(job(), ScanProfile()).allowlist is None


def test_l_affectation_porte_les_identifiants_nommes_par_le_profil():
    profile = ScanProfile(options={"web_auth": {"type": "form", "credential_id": 4}})

    a = assigner(vault=InMemoryCredentialVault([credential(4), credential(5)])).assignment_for(job(), profile)

    assert [c.id for c in a.credentials] == [4]
