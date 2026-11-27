"""
Le rafraîchissement du référentiel réécrit toujours le même fichier : il garde
une seule fiche par fichier, et sa planification survit aux redémarrages.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import worker_tasks
from app.core.platform_settings import (
    DATASET_REFRESH_KEY,
    DATASET_REFRESH_LAST_KEY,
    dataset_refresh_due,
    mark_dataset_refresh_queued,
    set_platform_setting,
)
from app.db import models

pytestmark = pytest.mark.integration

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def kev(tmp_path):
    path = tmp_path / "cisa_kev.json"
    path.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}))
    return str(path)


def fiches(db, kind="cisa_kev"):
    return db.query(models.CveDataset).filter(models.CveDataset.kind == kind).order_by(models.CveDataset.id).all()


def test_rafraichir_deux_fois_garde_une_seule_fiche_active(db, kev):
    worker_tasks._swap_dataset("cisa_kev", kev, db)
    premiere = fiches(db)[0].id

    worker_tasks._swap_dataset("cisa_kev", kev, db)

    assert [(d.id, d.name, d.enabled) for d in fiches(db)] == [(premiere, "kev_auto", True)]


def test_les_doublons_d_un_meme_fichier_disparaissent_au_rafraichissement(db, kev):
    db.add_all([
        models.CveDataset(id=1, name="kev_auto", kind="cisa_kev", path=kev, enabled=False),
        models.CveDataset(id=2, name="kev_auto", kind="cisa_kev", path=kev, enabled=True),
        models.CveDataset(id=3, name="kev_auto", kind="cisa_kev", path=kev, enabled=False),
    ])
    db.commit()

    worker_tasks._swap_dataset("cisa_kev", kev, db)

    assert [(d.id, d.enabled) for d in fiches(db)] == [(2, True)]


def test_un_fichier_d_un_autre_chemin_est_desactive_pas_supprime(db, kev):
    db.add(models.CveDataset(id=1, name="import", kind="cisa_kev", path="/data/cve/kev_import.json", enabled=True))
    db.add(models.CveDataset(id=2, name="epss_auto", kind="epss", path="/data/cve/epss.json", enabled=True))
    db.commit()

    worker_tasks._swap_dataset("cisa_kev", kev, db)

    assert [(d.path, d.enabled) for d in fiches(db)] == [("/data/cve/kev_import.json", False), (kev, True)]
    assert fiches(db, "epss")[0].enabled is True


def test_planification_desactivee_jamais_due(db):
    set_platform_setting(db, DATASET_REFRESH_KEY, {"enabled": False, "interval_hours": 24})

    assert dataset_refresh_due(db, NOW) is False


def test_jamais_lancee_due_tout_de_suite(db):
    set_platform_setting(db, DATASET_REFRESH_KEY, {"enabled": True, "interval_hours": 24})

    assert dataset_refresh_due(db, NOW) is True


def test_due_une_fois_l_intervalle_ecoule_depuis_le_dernier_lancement(db):
    set_platform_setting(db, DATASET_REFRESH_KEY, {"enabled": True, "interval_hours": 24})
    mark_dataset_refresh_queued(db, NOW)

    assert dataset_refresh_due(db, NOW + timedelta(hours=23, minutes=59)) is False
    assert dataset_refresh_due(db, NOW + timedelta(hours=24)) is True


def test_enregistrer_la_planification_ne_remet_pas_le_compteur_a_zero(db):
    set_platform_setting(db, DATASET_REFRESH_KEY, {"enabled": True, "interval_hours": 24})
    mark_dataset_refresh_queued(db, NOW)

    set_platform_setting(db, DATASET_REFRESH_KEY, {"enabled": True, "interval_hours": 12})

    assert dataset_refresh_due(db, NOW + timedelta(hours=12)) is True


def test_date_illisible_due_tout_de_suite(db):
    set_platform_setting(db, DATASET_REFRESH_KEY, {"enabled": True})
    set_platform_setting(db, DATASET_REFRESH_LAST_KEY, {"at": "hier"})

    assert dataset_refresh_due(db, NOW) is True
