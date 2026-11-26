"""
Les deux messages échangés entre la plateforme et ce qui exécute un scan :
l'affectation (le job à exécuter) et le rapport (ce qu'il a trouvé).
"""
import json

import pytest

from app.scan_jobs.assignment import (
    ScanAssignment,
    ScanReport,
    assign,
    finding_from_dict,
    referenced_credential_ids,
)
from app.scan_jobs.outcome import JobFailure
from app.scanner.profile import ScanProfile
from app.scanner.resources import CredentialError, CredentialLabel, InMemoryCredentialVault
from tests.fakes import UnreadableCredentialVault, credential, finding


def par_le_reseau(message):
    """Aller-retour JSON, comme sur le futur canal sonde <-> plateforme."""
    return type(message).from_dict(json.loads(json.dumps(message.to_dict())))


# ── Identifiants nommés par un profil ─────────────────────────────────────────

@pytest.mark.parametrize(("options", "ids"), [
    ({"auth": {"ssh_credential_id": 3}}, [3]),
    ({"ssh_auth": {"ssh_credential_id": "4"}}, [4]),
    ({"web_auth": {"type": "form", "credential_id": 5}}, [5]),
    ({"auth": {"ssh_credential_id": 3}, "ssh_auth": {"ssh_credential_id": 3}, "web_auth": {"credential_id": 1}}, [1, 3]),
    ({"auth": {"ssh_credential_id": None}, "web_auth": {"credential_id": "abc"}}, []),
    ({"auth": "pas un objet", "depth": 2}, []),
])
def test_les_identifiants_nommes_par_un_profil_sont_ceux_que_lisent_les_plugins(options, ids):
    assert referenced_credential_ids(options) == ids


def test_l_affectation_ne_porte_que_les_identifiants_nommes_par_le_profil():
    # Arrange
    vault = InMemoryCredentialVault([credential(3), credential(4)])
    profile = ScanProfile(options={"auth": {"ssh_credential_id": 3}, "web_auth": {"credential_id": 9}})

    # Act
    assignment = assign(10, 1, "10.0.0.5", "internal", profile, {}, vault)

    # Assert
    assert [c.id for c in assignment.credentials] == [3]
    assert assignment.credential_labels == (CredentialLabel(3, "cred-3"), CredentialLabel(4, "cred-4"))


def test_un_identifiant_illisible_reste_signale_au_plugin_qui_le_demande():
    profile = ScanProfile(options={"auth": {"ssh_credential_id": 3}})

    vault = assign(10, 1, "t", "internal", profile, {}, UnreadableCredentialVault()).credential_vault()

    with pytest.raises(CredentialError, match="cannot decrypt #3"):
        vault.get(3)


def test_la_representation_d_une_affectation_ne_montre_pas_les_secrets():
    assignment = ScanAssignment(10, 1, "t", "internal", credentials=(credential(3, secret="s3cret", passphrase="pp"),))

    assert "s3cret" not in repr(assignment) and "pp'" not in repr(assignment)


# ── Aller-retour par le réseau ────────────────────────────────────────────────

def test_une_affectation_traverse_le_reseau_sans_perte():
    assignment = ScanAssignment(
        job_id=10, workspace_id=1, target="https://app.corp", scan_type="external",
        profile=ScanProfile({"web.auth": True}, {"web_auth": {"type": "form", "credential_id": 3}}),
        meta={"web_auth": {"type": "form", "credential_id": 3}},
        credentials=(credential(3, secret_type="ssh_key", secret="KEY", passphrase="pp"),),
        credential_labels=(CredentialLabel(3, "cred-3"), CredentialLabel(4, "autre")),
        credential_errors={7: "cannot decrypt"},
    )

    assert par_le_reseau(assignment) == assignment


def test_un_rapport_traverse_le_reseau_sans_perte():
    report = ScanReport.succeeded(10, [
        finding("XSS", severity="high", references=["https://x"], cve="CVE-2024-1", is_kev=True, cvss=8.1),
        finding("Banner"),
    ])

    assert par_le_reseau(report) == report


def test_un_rapport_d_echec_traverse_le_reseau_sans_perte():
    report = ScanReport.failed(10, JobFailure("host unreachable", "scan_engine", "detail", "Traceback..."))

    assert par_le_reseau(report) == report


def test_un_constat_venu_d_une_version_plus_recente_garde_les_champs_connus():
    data = {"plugin_id": "p", "title": "T", "severity": "low", "champ_futur": 1}

    assert finding_from_dict(data) == finding("T", plugin_id="p", severity="low", fingerprint="")
