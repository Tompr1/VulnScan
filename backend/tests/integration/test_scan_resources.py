"""
Ressources de scan lues en base : les identifiants d'un seul client, et les
jeux de données de référence partagés par tous.
"""
import pytest

from app.cve.matcher import InMemoryCveCatalog
from app.db import models
from app.scanner.resources import CredentialError, CredentialLabel, ScanCredential
from app.scanner.sql_resources import SqlCredentialVault, SqlReferenceData


def chiffrer(valeur: str) -> str:
    return f"enc:{valeur}"


def dechiffrer(valeur: str) -> str:
    if not valeur.startswith("enc:"):
        raise ValueError("bad token")
    return valeur[4:]


@pytest.fixture
def identifiants(db, workspace):
    db.add_all([
        models.Credential(id=10, workspace_id=1, name="linux", username="root", secret_type="ssh_key",
                          secret_enc=chiffrer("KEY"), passphrase_enc=chiffrer("pp")),
        models.Credential(id=11, workspace_id=1, name="web", username="alice", secret_type="password",
                          secret_enc="illisible", passphrase_enc=None),
        models.Credential(id=20, workspace_id=2, name="autre client", username="bob", secret_type="password",
                          secret_enc=chiffrer("pw2")),
    ])
    db.commit()


def coffre(session_factory, workspace_id=1):
    return SqlCredentialVault(session_factory, workspace_id, decrypt=dechiffrer)


def test_le_coffre_rend_l_identifiant_du_client_dechiffre(session_factory, identifiants):
    credential = coffre(session_factory).get(10)

    assert credential == ScanCredential(10, "linux", "root", "ssh_key", "KEY", "pp")


def test_le_coffre_ne_rend_pas_l_identifiant_d_un_autre_client(session_factory, identifiants):
    assert coffre(session_factory).get(20) is None


def test_le_coffre_accepte_un_identifiant_ecrit_en_texte_dans_le_profil(session_factory, identifiants):
    assert coffre(session_factory).get("10").username == "root"


def test_le_coffre_ignore_un_identifiant_qui_n_est_pas_un_nombre(session_factory, identifiants):
    assert coffre(session_factory).get("abc") is None


def test_le_coffre_signale_un_secret_indechiffrable(session_factory, identifiants):
    with pytest.raises(CredentialError, match="Cannot decrypt credential #11"):
        coffre(session_factory).get(11)


def test_le_coffre_ignore_une_phrase_de_passe_indechiffrable(session_factory, db, identifiants):
    db.get(models.Credential, 10).passphrase_enc = "illisible"
    db.commit()

    assert coffre(session_factory).get(10).passphrase is None


def test_le_coffre_ne_liste_que_les_identifiants_du_client(session_factory, identifiants):
    assert coffre(session_factory).labels() == [CredentialLabel(10, "linux"), CredentialLabel(11, "web")]


def test_les_jeux_de_reference_actifs_sont_lus_du_plus_recent_au_plus_ancien(session_factory, db):
    # Arrange
    db.add_all([
        models.CveDataset(id=1, name="kev v1", kind="cisa_kev", path="/data/kev-1.json"),
        models.CveDataset(id=2, name="kev v2", kind="cisa_kev", path="/data/kev-2.json"),
        models.CveDataset(id=3, name="kev off", kind="cisa_kev", path="/data/kev-3.json", enabled=False),
        models.CveDataset(id=4, name="epss", kind="epss", path="/data/epss.json"),
    ])
    db.commit()
    reference = SqlReferenceData(session_factory, load_dataset=lambda path: [{"path": path}])

    # Act
    datasets = reference.datasets("cisa_kev")

    # Assert
    assert datasets == [[{"path": "/data/kev-2.json"}], [{"path": "/data/kev-1.json"}]]


def test_le_catalogue_cve_combine_la_base_et_les_jeux_nvd_tant_que_l_import_n_est_pas_fini(session_factory, db):
    db.add(models.CveDataset(id=1, name="nvd", kind="nvd_cpe_cve", path="/data/nvd.json"))
    db.commit()
    item = {"cve": "CVE-2024-6387", "matches": [{"cpe23": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}]}
    reference = SqlReferenceData(session_factory, load_dataset=lambda path: [item])

    records = reference.cve_catalog().records_for({("openbsd", "openssh")})

    assert [r.cve_id for r in records] == [r.cve_id for r in InMemoryCveCatalog.from_flattened([item]).records_for({("openbsd", "openssh")})]
