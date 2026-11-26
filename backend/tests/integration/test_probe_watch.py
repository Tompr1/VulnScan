"""
Le client est prévenu quand sa sonde se tait, puis quand elle revient — une
fois chaque fois, et pas parce que la plateforme elle-même a redémarré.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.db import models
from app.probes.watch import ProbeWatch
from tests.fakes import SpyNotifier

pytestmark = pytest.mark.integration

T0 = datetime(2026, 11, 26, 10, 0, tzinfo=timezone.utc)
SILENCE = timedelta(minutes=10)


class Horloge:
    def __init__(self):
        self.maintenant = T0

    def __call__(self):
        return self.maintenant

    def avance(self, **duree):
        self.maintenant += timedelta(**duree)


class Echoue:
    def probe_status(self, workspace_id, alert):
        raise RuntimeError("slack en panne")


@pytest.fixture
def monde(session_factory, db, workspace):
    db.add(models.Probe(id=1, workspace_id=1, name="Paris", status="active", last_seen_at=T0))
    db.add(models.Probe(id=2, workspace_id=1, name="Lyon", status="revoked", last_seen_at=T0 - timedelta(days=3)))
    db.add(models.Probe(id=3, workspace_id=1, name="Nantes", status="pending"))
    db.commit()
    horloge, notifier = Horloge(), SpyNotifier()
    watch = ProbeWatch(session_factory, notifier, horloge, SILENCE, "https://soc.example/#/root/probes")
    return watch, horloge, notifier, db


def vu(db, probe_id, quand):
    db.get(models.Probe, probe_id).last_seen_at = quand
    db.commit()


def journal(db, probe_id):
    db.expire_all()
    return [e.kind for e in db.query(models.ProbeEvent).filter_by(probe_id=probe_id).order_by(models.ProbeEvent.id)]


def test_une_sonde_qui_repond_ne_declenche_rien(monde):
    watch, horloge, notifier, db = monde
    horloge.avance(minutes=5)
    vu(db, 1, horloge())

    assert watch.check() == []


def test_une_sonde_muette_est_signalee_hors_ligne_une_seule_fois(monde):
    # Arrange
    watch, horloge, notifier, db = monde
    db.add(models.ScanJob(workspace_id=1, target="10.0.0.5", profile_id=5, status="queued", scan_type="internal",
                          runs_on="probe"))
    db.commit()
    horloge.avance(minutes=11)

    # Act
    [alerte] = watch.check()
    horloge.avance(minutes=30)
    encore = watch.check()

    # Assert
    assert (alerte.probe_name, alerte.client_name, alerte.online, alerte.waiting_jobs) == ("Paris", "main", False, 1)
    assert alerte.url == "https://soc.example/#/root/probes"
    assert "No contact for 11 min" in alerte.lines[0]
    assert encore == []
    assert notifier.alerts == [(1, alerte)]
    assert journal(db, 1) == ["offline"]


def test_une_sonde_qui_revient_est_annoncee_avec_la_duree_de_son_absence(monde):
    watch, horloge, notifier, db = monde
    horloge.avance(minutes=11)
    watch.check()
    horloge.avance(minutes=49)
    vu(db, 1, horloge())

    [retour] = watch.check()

    assert retour.online and "after 49 min offline" in retour.lines[0]
    db.expire_all()
    assert db.get(models.Probe, 1).offline_since is None
    assert journal(db, 1) == ["offline", "online"]


def test_apres_un_redemarrage_de_la_plateforme_les_sondes_ont_le_temps_de_revenir(session_factory, db, workspace):
    # La plateforme était arrêtée : la sonde n'a pas pu la joindre depuis 2 h.
    db.add(models.Probe(id=1, workspace_id=1, name="Paris", status="active", last_seen_at=T0 - timedelta(hours=2)))
    db.commit()
    horloge, notifier = Horloge(), SpyNotifier()
    watch = ProbeWatch(session_factory, notifier, horloge, SILENCE)

    horloge.avance(minutes=5)
    avant = watch.check()
    horloge.avance(minutes=6)
    apres = watch.check()

    assert avant == []
    assert [a.probe_name for a in apres] == ["Paris"]


def test_les_sondes_revoquees_ou_jamais_enrolees_ne_sont_pas_surveillees(monde):
    watch, horloge, _, db = monde
    vu(db, 1, T0 + timedelta(hours=1))
    horloge.avance(hours=1)

    assert watch.check() == []
    assert journal(db, 2) == journal(db, 3) == []


def test_une_integration_en_panne_n_empeche_pas_d_enregistrer_l_etat(session_factory, db, workspace):
    db.add(models.Probe(id=1, workspace_id=1, name="Paris", status="active", last_seen_at=T0))
    db.commit()
    horloge = Horloge()
    watch = ProbeWatch(session_factory, Echoue(), horloge, SILENCE)
    horloge.avance(minutes=11)

    assert len(watch.check()) == 1
    assert journal(db, 1) == ["offline"]
    assert watch.check() == []
