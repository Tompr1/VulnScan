"""
Le Threat Intel fusionne NVD, CISA KEV, EPSS et les avis éditeurs dans une
table, construite par le worker des datasets quand ils changent : l'API ne
fait que l'interroger, elle ne recharge plus jamais les fichiers.
"""
import json
import os
from datetime import date

import pytest

from app.cve.reference_datasets import REFRESH_LOCK_KEY, REFRESH_STATUS_KEY, clear_abandoned_refresh
from app.db import models
from app.threat_intel import aggregator

pytestmark = pytest.mark.integration

AUJOURD_HUI = date(2026, 11, 28)


class FauxRedis:
    def __init__(self):
        self.valeurs = {}

    def get(self, cle):
        return self.valeurs.get(cle)

    def set(self, cle, valeur, nx=False, ex=None):
        if nx and cle in self.valeurs:
            return None
        self.valeurs[cle] = valeur if isinstance(valeur, bytes) else str(valeur).encode()
        return True

    def setex(self, cle, ttl, valeur):
        self.set(cle, valeur)

    def exists(self, cle):
        return int(cle in self.valeurs)

    def delete(self, cle):
        self.valeurs.pop(cle, None)


def _ecrire(chemin, contenu):
    chemin.write_text(json.dumps(contenu))
    return str(chemin)


@pytest.fixture
def datasets(db, tmp_path):
    fichiers = {
        "nvd_cpe_cve": _ecrire(tmp_path / "nvd.json", [
            {"cve": "CVE-2024-0001", "summary": "Débordement dans Acme Tool", "cvss": 9.8, "severity": "CRITICAL",
             "matches": [{"cpe23": "cpe:2.3:a:acme:tool:1.0:*:*:*:*:*:*:*"}], "refs": ["https://acme.example/a"]},
            {"cve": "CVE-2024-0002", "summary": "Fuite dans Globex", "cvss": 7.5, "severity": "high"},
            {"cve": "CVE-2024-0003", "summary": "Bogue mineur 100%_sûr", "cvss": 3.1, "severity": "low"},
        ]),
        "cisa_kev": _ecrire(tmp_path / "kev.json", [
            {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Tool", "dateAdded": "2026-11-25",
             "dueDate": "2026-12-02", "knownRansomwareCampaignUse": "Known", "notes": "Exploitée"},
            {"cveID": "CVE-2024-0009", "vendorProject": "Initech", "product": "TPS", "dateAdded": "2026-01-10",
             "dueDate": "2026-02-01"},
        ]),
        "epss": _ecrire(tmp_path / "epss.json", [
            {"cve": "CVE-2024-0001", "epss": 0.92, "percentile": 0.99},
            {"cve": "CVE-2024-0002", "epss": 0.10, "percentile": 0.50},
            {"cve": "CVE-2099-9999", "epss": 0.9, "percentile": 0.9},
        ]),
        "vendor_advisories": _ecrire(tmp_path / "va.json", {
            "CVE-2024-0002": [
                {"vendor": "ubuntu", "id": "USN-1", "url": "https://ubuntu.example/usn-1"},
                {"vendor": "ubuntu", "id": "USN-1", "url": "https://ubuntu.example/usn-1"},
                {"vendor": "debian", "id": "DSA-2", "url": "https://debian.example/dsa-2"},
            ],
        }),
    }
    for i, (kind, chemin) in enumerate(fichiers.items(), start=1):
        db.add(models.CveDataset(id=i, name=kind, kind=kind, path=chemin, enabled=True))
    db.commit()
    assert aggregator.rebuild(db) is True
    return fichiers


# ── Construction ────────────────────────────────────────────────────────────

def test_la_fusion_reunit_les_quatre_sources_d_une_cve(db, datasets):
    cve = aggregator.detail(db, "cve-2024-0001", today=AUJOURD_HUI)

    assert cve["vendor"] == "Acme" and cve["severity"] == "critical"
    assert (cve["kev"], cve["ransomware"], cve["kev_added"], cve["kev_due"]) == (True, True, "2026-11-25", "2026-12-02")
    assert (cve["epss"], cve["epss_percentile"]) == (0.92, 0.99)
    assert cve["kev_notes"] == "Exploitée" and cve["refs"] == ["https://acme.example/a"]
    assert cve["matches"][0]["cpe23"].startswith("cpe:2.3:a:acme")
    # 9.8/10×40 + 0.99×35 + 12 (KEV) + 3 (rançongiciel) + 10 (ajoutée il y a 3 jours) = 98.85
    assert cve["threat_score"] == pytest.approx(98.85, abs=0.05)


def test_les_avis_editeurs_sont_dedoublonnes_par_url(db, datasets):
    avis = aggregator.detail(db, "CVE-2024-0002")["vendor_advisories"]

    assert {vendeur: [a["id"] for a in liste] for vendeur, liste in avis.items()} == {"ubuntu": ["USN-1"], "debian": ["DSA-2"]}


def test_une_cve_connue_seulement_d_epss_n_est_pas_creee(db, datasets):
    assert aggregator.detail(db, "CVE-2099-9999") is None
    assert aggregator.detail(db, "CVE-2024-0009")["vendor"] == "Initech"


def test_le_bonus_de_recence_suit_le_jour_de_lecture_pas_celui_de_la_construction(db, datasets):
    le_jour_meme = aggregator.detail(db, "CVE-2024-0001", today=AUJOURD_HUI)["threat_score"]
    six_mois_plus_tard = aggregator.detail(db, "CVE-2024-0001", today=date(2027, 5, 28))["threat_score"]

    assert round(le_jour_meme - six_mois_plus_tard, 1) == 10.0


def test_reconstruire_sans_changement_des_fichiers_ne_fait_rien(db, datasets):
    assert aggregator.rebuild_needed(db) is False
    assert aggregator.rebuild(db) is False


def test_un_fichier_reecrit_au_meme_chemin_declenche_la_reconstruction(db, datasets):
    _ecrire_kev_etendu(datasets["cisa_kev"])

    assert aggregator.rebuild_needed(db) is True
    assert aggregator.rebuild(db) is True
    assert aggregator.stats(db, today=AUJOURD_HUI)["kev_count"] == 3


def _ecrire_kev_etendu(chemin):
    with open(chemin, "w") as f:
        json.dump([{"cveID": "CVE-2024-0001"}, {"cveID": "CVE-2024-0009"}, {"cveID": "CVE-2024-0002"}], f)
    os.utime(chemin, ns=(1, 1))


def test_sans_aucun_dataset_la_table_est_vide(db):
    aggregator.rebuild(db)

    assert aggregator.stats(db)["total_cves"] == 0
    assert aggregator.query(db)["cves"] == []


# ── Lecture ─────────────────────────────────────────────────────────────────

def test_les_compteurs_sont_calcules_par_la_base(db, datasets):
    stats = aggregator.stats(db, today=AUJOURD_HUI)

    assert {k: stats[k] for k in (
        "total_cves", "kev_count", "kev_due_within_7d", "ransomware_count", "new_kev_7d",
        "high_epss_count", "critical_count", "high_count", "vendor_advisory_cve_count",
    )} == {
        "total_cves": 4, "kev_count": 2, "kev_due_within_7d": 1, "ransomware_count": 1, "new_kev_7d": 1,
        "high_epss_count": 1, "critical_count": 1, "high_count": 1, "vendor_advisory_cve_count": 1,
    }
    assert stats["datasets_loaded"] == ["nvd", "kev", "epss", "vendor_advisories"]
    assert stats["vendor_advisory_vendors"] == ["debian", "ubuntu"]
    assert stats["built_at"]


def test_la_liste_est_triee_par_score_de_menace_puis_paginee(db, datasets):
    premiere = aggregator.query(db, per_page=2, today=AUJOURD_HUI)
    seconde = aggregator.query(db, per_page=2, page=2, today=AUJOURD_HUI)

    assert (premiere["total"], premiere["total_pages"]) == (4, 2)
    # 0003 : 3.1/10×40 = 12.4 ; 0009 : KEV seule (12), ajoutée il y a plus de 90 jours
    assert [c["cve"] for c in premiere["cves"] + seconde["cves"]] == [
        "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0009",
    ]


@pytest.mark.parametrize(("filtres", "attendues"), [
    ({"q": "globex"}, ["CVE-2024-0002"]),
    ({"q": "acme"}, ["CVE-2024-0001"]),
    ({"q": "100%_"}, ["CVE-2024-0003"]),
    ({"q": "%"}, ["CVE-2024-0003"]),
    ({"severity": ["critical", "low"]}, ["CVE-2024-0001", "CVE-2024-0003"]),
    ({"kev_only": True}, ["CVE-2024-0001", "CVE-2024-0009"]),
    ({"ransomware_only": True}, ["CVE-2024-0001"]),
    ({"min_epss": 0.5}, ["CVE-2024-0001"]),
    ({"min_cvss": 7.0}, ["CVE-2024-0001", "CVE-2024-0002"]),
])
def test_les_filtres_de_la_liste(db, datasets, filtres, attendues):
    resultat = aggregator.query(db, sort="cvss", **filtres)

    assert sorted(c["cve"] for c in resultat["cves"]) == attendues


@pytest.mark.parametrize("ordre", ["asc", "desc"])
def test_les_cve_sans_echeance_kev_passent_en_dernier_dans_les_deux_sens(db, datasets, ordre):
    cves = [c["cve"] for c in aggregator.query(db, sort="kev_due", order=ordre)["cves"]]

    attendu_kev = ["CVE-2024-0009", "CVE-2024-0001"] if ordre == "asc" else ["CVE-2024-0001", "CVE-2024-0009"]
    assert cves[:2] == attendu_kev
    assert sorted(cves[2:]) == ["CVE-2024-0002", "CVE-2024-0003"]


def test_la_liste_ne_renvoie_qu_un_resume_tronque(db, tmp_path):
    db.add(models.CveDataset(id=1, name="nvd", kind="nvd_cpe_cve", enabled=True,
                             path=_ecrire(tmp_path / "nvd.json", [{"cve": "CVE-2024-0001", "summary": "x" * 500}])))
    db.commit()
    aggregator.rebuild(db)

    ligne = aggregator.query(db)["cves"][0]

    assert len(ligne["summary"]) == 240 and "matches" not in ligne
    assert len(aggregator.detail(db, "CVE-2024-0001")["summary"]) == 500


# ── Mise en file de la reconstruction ───────────────────────────────────────

def test_le_planificateur_met_la_reconstruction_en_file_une_seule_fois(db, datasets):
    _ecrire_kev_etendu(datasets["cisa_kev"])
    redis, files = FauxRedis(), []

    premiere = aggregator.queue_rebuild_if_needed(db, redis, lambda: files.append("rebuild"))
    seconde = aggregator.queue_rebuild_if_needed(db, redis, lambda: files.append("rebuild"))

    assert (premiere, seconde, files) == (True, False, ["rebuild"])


def test_le_planificateur_ne_fait_rien_si_les_datasets_n_ont_pas_change(db, datasets):
    files = []

    assert aggregator.queue_rebuild_if_needed(db, FauxRedis(), lambda: files.append("rebuild")) is False
    assert files == []


def test_le_planificateur_laisse_la_synchro_en_cours_reconstruire_a_sa_fin(db, datasets):
    _ecrire_kev_etendu(datasets["cisa_kev"])
    redis, files = FauxRedis(), []
    redis.set(REFRESH_LOCK_KEY, "job-1")

    assert aggregator.queue_rebuild_if_needed(db, redis, lambda: files.append("rebuild")) is False
    assert files == []


def test_une_mise_en_file_echouee_ne_bloque_pas_la_suivante():
    redis = FauxRedis()

    def file_indisponible():
        raise RuntimeError("redis down")

    with pytest.raises(RuntimeError):
        aggregator.request_rebuild(redis, file_indisponible)
    assert aggregator.request_rebuild(redis, lambda: None) is True


# ── Synchro interrompue ─────────────────────────────────────────────────────

def _synchro_en_cours(redis, job_id="job-1"):
    redis.set(REFRESH_LOCK_KEY, job_id)
    redis.setex(REFRESH_STATUS_KEY, 3600, json.dumps({
        "status": "running", "current_kind": "vendor_advisories", "finished_at": None,
        "kinds": {"epss": {"status": "done", "message": ""},
                  "vendor_advisories": {"status": "running", "message": ""},
                  "compliance_map": {"status": "pending", "message": ""}},
    }))


def test_une_synchro_dont_le_worker_a_ete_tue_libere_son_verrou(db):
    redis = FauxRedis()
    _synchro_en_cours(redis)

    assert clear_abandoned_refresh(redis, lambda job_id: "failed") is True

    etat = json.loads(redis.get(REFRESH_STATUS_KEY))
    assert not redis.exists(REFRESH_LOCK_KEY)
    assert (etat["status"], etat["current_kind"]) == ("partial", None) and etat["finished_at"]
    assert etat["kinds"]["vendor_advisories"]["status"] == "failed"
    assert etat["kinds"]["compliance_map"]["status"] == "pending"


@pytest.mark.parametrize("statut", [None, "failed", "stopped", "canceled", "finished"])
def test_un_verrou_sans_job_vivant_est_abandonne(statut):
    redis = FauxRedis()
    _synchro_en_cours(redis)

    assert clear_abandoned_refresh(redis, lambda job_id: statut) is True


@pytest.mark.parametrize("statut", ["queued", "started"])
def test_une_synchro_qui_tourne_garde_son_verrou(statut):
    redis = FauxRedis()
    _synchro_en_cours(redis)

    assert clear_abandoned_refresh(redis, lambda job_id: statut) is False
    assert redis.exists(REFRESH_LOCK_KEY)
    assert json.loads(redis.get(REFRESH_STATUS_KEY))["status"] == "running"


def test_sans_verrou_il_n_y_a_rien_a_liberer():
    assert clear_abandoned_refresh(FauxRedis(), lambda job_id: None) is False
