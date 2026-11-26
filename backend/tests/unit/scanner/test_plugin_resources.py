"""
Les plugins lisent les identifiants du client et les données de référence
dans ``ctx.resources``, jamais dans la base : c'est ce qui leur permettra de
tourner sur une sonde installée chez le client, sans base de données.
"""
import asyncio

from app.cve.matcher import InMemoryCveCatalog
from app.scanner.plugins import (
    cis_benchmark,
    cisa_kev,
    cms_match,
    cve_packages,
    nvd_match,
    sca_server,
    ssh_inventory,
    web_auth,
)
from app.scanner.resources import InMemoryCredentialVault, InMemoryReferenceData, ScanResources
from tests.fakes import UnreadableCredentialVault, credential, plugin_context, scan_resources

TARGET = "10.0.0.5"


def run(module, ctx):
    return asyncio.run(module.Check(module.META).run(TARGET, ctx))


def nvd_item(cve_id, cpe23, **versions):
    return {"cve": cve_id, "summary": f"{cve_id} summary", "severity": "high", "cvss": 8.1,
            "refs": [], "matches": [{"cpe23": cpe23, **versions}]}


OPENSSH_CATALOG = InMemoryCveCatalog.from_flattened([
    nvd_item("CVE-2024-6387", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
             versionStartIncluding="8.5", versionEndExcluding="9.8"),
])


# ── Identifiants ──────────────────────────────────────────────────────────────

def test_l_inventaire_ssh_signale_un_identifiant_absent_et_liste_ceux_du_client():
    # Arrange
    ctx = plugin_context(
        scan_resources(credential(3, name="serveurs-linux")),
        net__open_ports=[22],
        profile_options={"auth": {"ssh_credential_id": 99}},
    )

    # Act
    result = run(ssh_inventory, ctx)

    # Assert
    [finding] = result.findings
    assert finding.title == "SSH credential #99 not found"
    assert "#3 (serveurs-linux)" in finding.evidence


def test_l_inventaire_ssh_se_connecte_avec_le_secret_en_clair(monkeypatch):
    # Arrange
    calls = []

    def fake_ssh(host, port, username, secret_type, secret, passphrase, timeout):
        calls.append((host, port, username, secret_type, secret, passphrase))
        return {"os_release": 'PRETTY_NAME="Debian 12"', "dpkg": ""}

    monkeypatch.setattr(ssh_inventory, "ssh_inventory", fake_ssh)
    ctx = plugin_context(
        scan_resources(credential(3, username="root", secret_type="ssh_key", secret="KEY", passphrase="pp")),
        net__open_ports=[22],
        profile_options={"auth": {"ssh_credential_id": 3, "ssh_port": 2200}},
    )

    # Act
    result = run(ssh_inventory, ctx)

    # Assert
    assert calls == [(TARGET, 2200, "root", "ssh_key", "KEY", "pp")]
    assert result.artifacts["inventory.os"]["os_release"]["PRETTY_NAME"] == "Debian 12"


def test_l_inventaire_ssh_signale_un_identifiant_indechiffrable():
    ctx = plugin_context(
        ScanResources(UnreadableCredentialVault(), InMemoryReferenceData()),
        net__open_ports=[22],
        profile_options={"auth": {"ssh_credential_id": 3}},
    )

    result = run(ssh_inventory, ctx)

    [finding] = result.findings
    assert finding.title == "SSH inventory failed"
    assert "cannot decrypt #3" in finding.evidence


def test_le_benchmark_cis_ignore_un_identifiant_que_le_client_n_a_pas():
    ctx = plugin_context(
        scan_resources(credential(3)),
        net__open_ports=[22],
        profile_options={"auth": {"ssh_credential_id": 4}},
    )

    result = run(cis_benchmark, ctx)

    assert [f.title for f in result.findings] == ["CIS Benchmark requires SSH credentials"]


def test_le_benchmark_cis_se_connecte_avec_l_identifiant_du_client(monkeypatch):
    # Arrange
    calls = []

    def fake_exec(host, port, user, password=None, key_text=None, command="", timeout=10):
        calls.append((host, port, user, password, key_text))
        return "ERROR: refused"

    monkeypatch.setattr(cis_benchmark, "_ssh_exec", fake_exec)
    ctx = plugin_context(
        scan_resources(credential(3, username="admin", secret="pw")),
        net__open_ports=[22],
        profile_options={"auth": {"ssh_credential_id": 3}},
    )

    # Act
    result = run(cis_benchmark, ctx)

    # Assert
    assert calls == [(TARGET, 22, "admin", "pw", None)]
    assert [f.title for f in result.findings] == ["CIS Benchmark: SSH connection failed"]


def test_l_audit_sca_serveur_ignore_un_identifiant_que_le_client_n_a_pas():
    # Avant, ce plugin lisait l'identifiant sans filtrer sur le client.
    ctx = plugin_context(
        scan_resources(),
        net__open_ports=[22],
        profile_options={"auth": {"ssh_credential_id": 4}},
    )

    result = run(sca_server, ctx)

    assert [f.title for f in result.findings] == ["Server SCA requires SSH credentials"]


def test_l_audit_sca_serveur_se_connecte_avec_l_identifiant_du_client(monkeypatch):
    # Arrange
    connections = []

    class FakeSshClient:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            connections.append(kwargs)
            raise OSError("refused")

    monkeypatch.setattr(sca_server.paramiko, "SSHClient", FakeSshClient)
    ctx = plugin_context(
        scan_resources(credential(4, username="deploy", secret="pw")),
        net__open_ports=[22],
        profile_options={"ssh_auth": {"ssh_credential_id": 4}},
    )

    # Act
    result = run(sca_server, ctx)

    # Assert
    assert [(c["username"], c["password"]) for c in connections] == [("deploy", "pw")]
    assert [f.title for f in result.findings] == ["Server SCA: SSH connection failed"]


def test_l_authentification_web_complete_un_jeton_bearer_avec_le_secret():
    vault = InMemoryCredentialVault([credential(7, secret="tok")])

    config, error = web_auth._resolve_credential({"type": "bearer", "credential_id": 7}, vault)

    assert (config, error) == ({"type": "bearer", "token": "tok"}, "")


def test_l_authentification_web_garde_les_champs_saisis_dans_le_profil():
    vault = InMemoryCredentialVault([credential(7, username="alice", secret="pw")])

    config, error = web_auth._resolve_credential({"type": "form", "credential_id": 7, "username": "bob"}, vault)

    assert (config, error) == ({"type": "form", "username": "bob", "password": "pw"}, "")


def test_l_authentification_web_signale_un_identifiant_absent():
    config, error = web_auth._resolve_credential({"type": "form", "credential_id": 7}, InMemoryCredentialVault())

    assert config == {"type": "form", "credential_id": 7}
    assert error == "credential #7 not found in workspace"


def test_l_authentification_web_signale_un_identifiant_indechiffrable():
    _, error = web_auth._resolve_credential({"type": "form", "credential_id": 7}, UnreadableCredentialVault())

    assert error.startswith("could not decrypt credential #7")


# ── Données de référence ──────────────────────────────────────────────────────

def test_la_priorisation_kev_marque_les_cve_detectees_qui_sont_exploitees():
    # Arrange
    kev = [[{"cve": "CVE-2024-6387", "vendorProject": "OpenBSD", "product": "OpenSSH", "dueDate": "2025-01-01"}]]
    ctx = plugin_context(
        scan_resources(datasets={"cisa_kev": kev}),
        cve__nvd_hits=[{"cve": "CVE-2024-6387"}, {"cve": "CVE-2023-0001"}],
    )

    # Act
    result = run(cisa_kev, ctx)

    # Assert
    assert [(f.cve, f.is_kev, f.severity) for f in result.findings] == [("CVE-2024-6387", True, "critical")]


def test_la_priorisation_kev_ne_trouve_rien_sans_jeu_de_donnees():
    ctx = plugin_context(scan_resources(), cve__nvd_hits=[{"cve": "CVE-2024-6387"}])

    result = run(cisa_kev, ctx)

    assert result.findings == []


def test_la_correspondance_cms_ne_retient_que_les_cms_detectes():
    # Arrange
    cms_map = [[
        {"cve": "CVE-2024-1111", "cms": "wordpress", "severity": "high"},
        {"cve": "CVE-2024-2222", "cms": "drupal"},
    ]]
    ctx = plugin_context(
        scan_resources(datasets={"cms_cve_map": cms_map}),
        fingerprint__webtech=[{"name": "wordpress", "type": "cms"}],
    )

    # Act
    result = run(cms_match, ctx)

    # Assert
    assert [(f.cve, f.severity) for f in result.findings] == [("CVE-2024-1111", "high")]


def test_la_correspondance_nvd_cherche_dans_le_catalogue_des_ressources():
    ctx = plugin_context(
        scan_resources(catalog=OPENSSH_CATALOG),
        cpe__candidates=[{"cpe23": "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", "version": "9.6"}],
    )

    result = run(nvd_match, ctx)

    assert [f.cve for f in result.findings] == ["CVE-2024-6387"]
    assert [h["cve"] for h in result.artifacts["cve.nvd_hits"]] == ["CVE-2024-6387"]


def test_la_correspondance_des_paquets_lit_les_jeux_osv_et_le_catalogue_nvd():
    # Arrange
    osv = [[{
        "id": "OSV-1", "cve": "CVE-2024-3333", "ecosystem": "deb", "package": "libfoo",
        "ranges": [{"type": "introduced_fixed", "introduced": "1.0", "fixed": "1.5"}],
    }]]
    packages = [
        {"name": "libfoo", "version": "1.2", "ecosystem": "deb", "installed": True},
        {"name": "openssh-server", "version": "9.6", "ecosystem": "deb", "installed": True},
    ]
    ctx = plugin_context(
        scan_resources(datasets={"osv": osv}, catalog=OPENSSH_CATALOG),
        inventory__packages=packages,
    )

    # Act
    result = run(cve_packages, ctx)

    # Assert
    assert {f.cve for f in result.findings} == {"CVE-2024-3333", "CVE-2024-6387"}
