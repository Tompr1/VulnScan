"""
Ce qu'une sonde peut faire sur la plateforme : s'enrôler, s'authentifier,
prendre les jobs de SON client, rendre compte, lire le référentiel.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.core.crypto import encrypt_str
from app.cve.matcher import CveRecord
from app.db import models
from app.probes import secrets
from app.probes.gateway import InvalidMessage, ProbeGateway, UnknownDataset, UnknownJob
from app.probes.registry import ACTIVE, OFFLINE, ONLINE, PENDING, REVOKED, EnrollmentError, ProbeRegistry, display_status
from app.scan_jobs.assigner import JobAssigner
from app.scan_jobs.assignment import ScanReport
from app.scan_jobs.repository import SqlScanJobRepository
from app.scanner.allowlist import AllowlistPolicy
from app.scanner.sql_resources import SqlCredentialVault
from tests.fakes import SpyCancellationSignal, SpyJobQueue, finding

pytestmark = pytest.mark.integration

CLIENT, VOISIN = 1, 2
TTL = timedelta(hours=24)


class Horloge:
    def __init__(self):
        self.maintenant = datetime(2026, 11, 26, 10, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.maintenant


class Allowlists:
    def policy_for(self, workspace_id):
        return AllowlistPolicy.from_setting({CLIENT: "10.0.0.0/8", VOISIN: "192.168.0.0/16"}[workspace_id])


class Plateforme:
    def __init__(self, session_factory, db):
        self.db = db
        self.horloge = Horloge()
        self.file = SpyJobQueue()
        self.annulations = SpyCancellationSignal()
        self.jeux = {}
        self.gateway = ProbeGateway(
            session_factory,
            JobAssigner(SqlScanJobRepository(session_factory), lambda ws: SqlCredentialVault(session_factory, ws), Allowlists()),
            self.file,
            self.annulations,
            self.horloge,
            TTL,
            load_dataset=lambda path: self.jeux.get(path, []),
        )

    def sonde(self, workspace_id=CLIENT, nom="sonde"):
        """Une sonde créée puis enrôlée : son identité et son identifiant."""
        enrollment = ProbeRegistry(self.db, TTL).create(workspace_id, nom, self.horloge())
        identite, secret = self.gateway.enroll(enrollment.token, "probe-01", "1.0.0", "203.0.113.7")
        return identite, f"{secrets.SCHEME} {secrets.credential(identite.id, secret)}"

    def job(self, job_id, workspace_id=CLIENT, runs_on="probe", status="queued", profile_id=5, minutes=0, **kwargs):
        self.db.add(models.ScanJob(
            id=job_id, workspace_id=workspace_id, target="10.0.0.5", profile_id=profile_id, status=status,
            scan_type="internal", runs_on=runs_on, created_at=self.horloge() + timedelta(minutes=minutes), **kwargs,
        ))
        self.db.commit()

    def statut(self, job_id):
        self.db.expire_all()
        return self.db.get(models.ScanJob, job_id).status


@pytest.fixture
def p(session_factory, db, workspace):
    return Plateforme(session_factory, db)


# ── Enrôlement et authentification ────────────────────────────────────────────

def test_une_sonde_enrolee_s_authentifie_avec_son_identifiant(p):
    identite, authorization = p.sonde()

    assert p.gateway.authenticate(authorization, "203.0.113.7") == identite
    assert identite.workspace_id == CLIENT


def test_le_jeton_d_enrolement_ne_sert_qu_une_fois(p):
    enrollment = ProbeRegistry(p.db, TTL).create(CLIENT, "sonde", p.horloge())
    p.gateway.enroll(enrollment.token, "h", "v", "ip")

    with pytest.raises(EnrollmentError):
        p.gateway.enroll(enrollment.token, "h", "v", "ip")


def test_un_jeton_d_enrolement_expire_est_refuse(p):
    enrollment = ProbeRegistry(p.db, TTL).create(CLIENT, "sonde", p.horloge())
    p.horloge.maintenant += TTL + timedelta(seconds=1)

    with pytest.raises(EnrollmentError):
        p.gateway.enroll(enrollment.token, "h", "v", "ip")


def test_seul_le_condense_des_secrets_est_stocke(p):
    enrollment = ProbeRegistry(p.db, TTL).create(CLIENT, "sonde", p.horloge())
    identite, secret = p.gateway.enroll(enrollment.token, "h", "v", "ip")

    p.db.expire_all()
    stored = p.db.get(models.Probe, identite.id)
    assert stored.secret_hash == secrets.digest(secret)
    assert secret not in json.dumps({c.name: str(getattr(stored, c.name)) for c in models.Probe.__table__.columns})


@pytest.mark.parametrize("authorization", [
    None, "", "Bearer abc", "Probe abc", "Probe 1", "Probe 1.", "Probe x.secret",
])
def test_un_en_tete_mal_forme_n_authentifie_personne(p, authorization):
    p.sonde()

    assert p.gateway.authenticate(authorization, "ip") is None


def test_un_mauvais_secret_n_authentifie_pas(p):
    identite, _ = p.sonde()

    assert p.gateway.authenticate(f"Probe {identite.id}.faux-secret", "ip") is None


def test_une_sonde_revoquee_ne_s_authentifie_plus_et_ne_peut_pas_etre_reenrolee(p):
    identite, authorization = p.sonde()
    registry = ProbeRegistry(p.db, TTL)
    registry.revoke(p.db.get(models.Probe, identite.id), p.horloge())

    assert p.gateway.authenticate(authorization, "ip") is None
    with pytest.raises(Exception, match="revoked"):
        registry.new_enrollment(p.db.get(models.Probe, identite.id), p.horloge())


def test_un_nouvel_enrolement_remplace_le_secret_de_l_ancienne_installation(p):
    identite, ancien = p.sonde()
    enrollment = ProbeRegistry(p.db, TTL).new_enrollment(p.db.get(models.Probe, identite.id), p.horloge())

    _, nouveau = p.gateway.enroll(enrollment.token, "h", "v", "ip")

    assert p.gateway.authenticate(ancien, "ip") is None
    assert p.gateway.authenticate(f"Probe {identite.id}.{nouveau}", "ip") == identite


def test_le_statut_affiche_distingue_en_ligne_et_hors_ligne(p):
    identite, authorization = p.sonde()
    sonde = p.db.get(models.Probe, identite.id)
    p.db.refresh(sonde)
    en_attente = models.Probe(status=PENDING)

    statuts = [
        display_status(sonde, p.horloge() + timedelta(seconds=60), online_seconds=120),
        display_status(sonde, p.horloge() + timedelta(seconds=180), online_seconds=120),
        display_status(en_attente, p.horloge(), online_seconds=120),
        display_status(models.Probe(status=REVOKED), p.horloge(), online_seconds=120),
    ]

    assert sonde.status == ACTIVE
    assert statuts == [ONLINE, OFFLINE, PENDING, REVOKED]


# ── Prise en charge des jobs ──────────────────────────────────────────────────

def test_la_sonde_prend_le_plus_ancien_job_de_son_client_qui_l_attend(p):
    # Arrange
    identite, _ = p.sonde()
    p.job(20, minutes=2)
    p.job(21, minutes=1)
    p.job(22, minutes=0, runs_on="platform")
    p.job(23, minutes=0, workspace_id=VOISIN, profile_id=6)
    p.job(24, minutes=0, status="cancelled")

    # Act
    affectation = p.gateway.next_assignment(identite)

    # Assert
    assert affectation.job_id == 21
    assert p.statut(21) == "running"
    assert p.db.get(models.ScanJob, 21).probe_id == identite.id


def test_sans_job_en_attente_la_sonde_ne_recoit_rien(p):
    identite, _ = p.sonde()
    p.job(23, workspace_id=VOISIN, profile_id=6)

    assert p.gateway.next_assignment(identite) is None
    assert p.statut(23) == "queued"


def test_deux_sondes_du_meme_client_ne_prennent_jamais_le_meme_job(p):
    premiere, _ = p.sonde(nom="a")
    seconde, _ = p.sonde(nom="b")
    p.job(20)

    affectations = [p.gateway.next_assignment(premiere), p.gateway.next_assignment(seconde)]

    assert [a.job_id if a else None for a in affectations] == [20, None]


def test_l_affectation_porte_les_identifiants_du_profil_et_l_allowlist_du_client(p):
    # Arrange
    identite, _ = p.sonde()
    p.db.add(models.Credential(id=30, workspace_id=CLIENT, name="linux", username="root",
                               secret_enc=encrypt_str("pw"), secret_type="password"))
    p.db.get(models.Profile, 5).options_json = json.dumps({"auth": {"ssh_credential_id": 30}})
    p.db.commit()
    p.job(20)

    # Act
    affectation = p.gateway.next_assignment(identite)

    # Assert
    assert [(c.id, c.secret) for c in affectation.credentials] == [(30, "pw")]
    assert affectation.allowlist == "10.0.0.0/8"


def test_un_job_qui_ne_peut_pas_tourner_est_mis_en_echec_et_le_suivant_est_donne(p):
    identite, _ = p.sonde()
    p.job(20, minutes=0, profile_id=None)
    p.job(21, minutes=1)

    affectation = p.gateway.next_assignment(identite)

    assert affectation.job_id == 21
    [(job_id, rapport)] = p.file.reports
    assert (job_id, ScanReport.from_dict(rapport).failure.error) == (20, "Profile not found")


# ── Compte rendu ──────────────────────────────────────────────────────────────

def test_la_progression_est_enregistree_et_l_annulation_transmise(p):
    identite, _ = p.sonde()
    p.job(20)
    p.gateway.next_assignment(identite)
    p.annulations.request(20)

    stop = p.gateway.progress(identite, 20, {"progress": {"pct": 40}})

    assert stop is True
    p.db.expire_all()
    assert json.loads(p.db.get(models.ScanJob, 20).meta_json) == {"progress": {"pct": 40}}


@pytest.mark.parametrize("document", [[], {"pct": 40}, {"progress": "40%"}, {"progress": {"x": "y" * 70_000}}])
def test_une_progression_mal_formee_est_refusee(p, document):
    identite, _ = p.sonde()
    p.job(20)
    p.gateway.next_assignment(identite)

    with pytest.raises(InvalidMessage):
        p.gateway.progress(identite, 20, document)


def test_le_rapport_est_mis_en_file_pour_etre_finalise(p):
    identite, _ = p.sonde()
    p.job(20)
    p.gateway.next_assignment(identite)
    rapport = ScanReport.succeeded(20, [finding("XSS")]).to_dict()

    p.gateway.report(identite, 20, rapport)

    assert p.file.reports == [(20, rapport)]


def test_un_rapport_qui_nomme_un_autre_job_est_refuse(p):
    identite, _ = p.sonde()
    p.job(20)
    p.gateway.next_assignment(identite)

    with pytest.raises(InvalidMessage):
        p.gateway.report(identite, 20, ScanReport.succeeded(21, []).to_dict())


@pytest.mark.parametrize("donnees", [{}, {"job_id": "x"}, {"job_id": 20, "findings": [{"title": "sans plugin"}]}])
def test_un_rapport_illisible_est_refuse(p, donnees):
    identite, _ = p.sonde()
    p.job(20)
    p.gateway.next_assignment(identite)

    with pytest.raises(InvalidMessage):
        p.gateway.report(identite, 20, donnees)


def test_une_sonde_ne_peut_rendre_compte_que_de_ses_jobs_en_cours(p):
    # Arrange : un job pris par une autre sonde du client, un job du voisin
    # pris par la sonde du voisin, un job de la sonde déjà terminé.
    identite, _ = p.sonde()
    autre, _ = p.sonde(nom="autre")
    voisine, _ = p.sonde(VOISIN, "voisine")
    p.job(20)
    p.gateway.next_assignment(autre)
    p.job(21, workspace_id=VOISIN, profile_id=6)
    p.gateway.next_assignment(voisine)
    p.job(22, status="done", probe_id=identite.id)

    # Act / Assert
    for job_id in (20, 21, 22, 404):
        with pytest.raises(UnknownJob):
            p.gateway.progress(identite, job_id, {"progress": {}})
        with pytest.raises(UnknownJob):
            p.gateway.report(identite, job_id, ScanReport.succeeded(job_id, []).to_dict())
    assert p.file.reports == []


# ── Référentiel ───────────────────────────────────────────────────────────────

def test_un_jeu_de_donnees_est_servi_avec_une_version_qui_change_avec_lui(p, tmp_path):
    # Arrange
    fichier = tmp_path / "kev.json"
    fichier.write_text("[]")
    p.db.add(models.CveDataset(id=1, name="kev", kind="cisa_kev", path=str(fichier)))
    p.db.commit()
    p.jeux[str(fichier)] = [{"cve": "CVE-2024-1"}]

    # Act
    avant = p.gateway.dataset("cisa_kev")
    fichier.write_text('[{"cve": "CVE-2024-1"}]')
    apres = p.gateway.dataset("cisa_kev")

    # Assert
    assert avant.content == [[{"cve": "CVE-2024-1"}]]
    assert avant.etag != apres.etag
    assert p.gateway.reference_status()["datasets"]["cisa_kev"] == apres.etag


def test_seuls_les_jeux_lus_par_les_plugins_sont_servis(p):
    with pytest.raises(UnknownDataset):
        p.gateway.dataset("compliance_map")


def test_les_cve_d_un_produit_sont_servies_sous_la_forme_que_la_sonde_relit(p):
    item = {"cve": "CVE-2024-6387", "summary": "s", "severity": "high", "cvss": 8.1, "refs": ["https://r"],
            "matches": [{"cpe23": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                         "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"}]}
    p.db.add(models.CveEntry(cve_id="CVE-2024-6387", summary="s", severity="high", cvss=8.1,
                             references_json=json.dumps(["https://r"])))
    p.db.add(models.CveCpeMatch(cve_id="CVE-2024-6387", part="a", vendor="openbsd", product="openssh",
                                version="*", start_including="8.5", end_excluding="9.8"))
    p.db.commit()

    records = p.gateway.cve_records([["OpenBSD", "OpenSSH"]])

    assert [CveRecord.from_flattened(r) for r in records] == [CveRecord.from_flattened(item)]


@pytest.mark.parametrize("produits", ["openssh", [["openbsd"]], [["openbsd", 3]], [["", "x"]], [["a", "b"]] * 5001])
def test_une_recherche_de_cve_mal_formee_est_refusee(p, produits):
    with pytest.raises(InvalidMessage):
        p.gateway.cve_records(produits)
