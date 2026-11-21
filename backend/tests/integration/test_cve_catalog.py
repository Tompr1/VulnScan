from datetime import datetime, timezone

import pytest

from app.cve.catalogs import CompositeCveCatalog, workspace_cve_catalog
from app.cve.cpe import Cpe
from app.cve.matcher import InMemoryCveCatalog, ProductCandidate, find_vulnerabilities
from app.cve.nvd import parse_vulnerability
from app.cve.nvd_sync import SyncState
from app.cve.sql_catalog import SqlCveCatalog, SqlSyncStateStore
from app.db import models
from tests.unit.cve.nvd_fixtures import cpe_match, nvd_entry

pytestmark = pytest.mark.integration


def nvd(cve_id, *matches, **kwargs):
    return parse_vulnerability(nvd_entry(cve_id, matches=matches, **kwargs))


@pytest.fixture
def catalog(session_factory):
    return SqlCveCatalog(session_factory)


def test_le_catalogue_ne_renvoie_que_les_cve_des_produits_demandes(catalog):
    catalog.upsert([nvd("CVE-2024-6387", cpe_match("openbsd", "openssh", versionEndExcluding="9.8"), cvss=8.1),
                    nvd("CVE-2021-41773", cpe_match("apache", "http_server", "2.4.49"))])

    records = catalog.records_for({("openbsd", "openssh")})

    assert [(r.cve_id, r.cvss) for r in records] == [("CVE-2024-6387", 8.1)]
    assert records[0].matches[0].versions.end_excluding == "9.8"


def test_une_cve_mise_a_jour_remplace_ses_anciennes_configurations(catalog):
    catalog.upsert([nvd("CVE-2025-1", cpe_match("acme", "tool", versionEndExcluding="2.0"))])

    catalog.upsert([nvd("CVE-2025-1", cpe_match("acme", "tool", versionEndExcluding="3.0"))])

    matches = catalog.records_for({("acme", "tool")})[0].matches
    assert [m.versions.end_excluding for m in matches] == ["3.0"]
    assert catalog.count() == 1


def test_un_editeur_rachete_est_retrouve_sous_son_nom_canonique(catalog):
    catalog.upsert([nvd("CVE-2010-1", cpe_match("sun", "jdk", versionEndIncluding="1.6"))])

    hits = find_vulnerabilities(catalog, [ProductCandidate(Cpe.parse("cpe:2.3:a:oracle:jdk:1.6:*:*:*:*:*:*:*"), "1.6")])

    assert [h.record.cve_id for h in hits] == ["CVE-2010-1"]


def test_la_progression_de_synchronisation_est_persistee(session_factory):
    store = SqlSyncStateStore(session_factory)
    moment = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)

    store.save(SyncState(full_import_started_at=moment, full_import_next_index=4200, full_import_total=310000))

    loaded = store.load()
    assert (loaded.full_import_next_index, loaded.full_import_total, loaded.full_import_done) == (4200, 310000, False)


def test_un_catalogue_composite_donne_priorite_au_premier_pour_une_meme_cve():
    product = cpe_match("acme", "tool")
    first = InMemoryCveCatalog([nvd("CVE-1", product, cvss=9.0).record])
    second = InMemoryCveCatalog([nvd("CVE-1", product, cvss=1.0).record, nvd("CVE-2", product).record])

    records = CompositeCveCatalog([first, second]).records_for({("acme", "tool")})

    assert [(r.cve_id, r.cvss) for r in records] == [("CVE-1", 9.0), ("CVE-2", None)]


def test_pendant_l_import_complet_le_scan_utilise_aussi_les_jeux_json(session_factory, db, workspace, catalog):
    # Arrange
    catalog.upsert([nvd("CVE-2000-1", cpe_match("acme", "tool"))])
    db.add(models.CveDataset(workspace_id=1, name="nvd", kind="nvd_cpe_cve", path="/data/cve/nvd.json", enabled=True))
    db.commit()
    json_items = [{"cve": "CVE-2026-1", "matches": [{"cpe23": "cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*"}]}]

    # Act
    records = workspace_cve_catalog(1, session_factory, load_dataset=lambda path: json_items).records_for({("acme", "tool")})

    # Assert
    assert {r.cve_id for r in records} == {"CVE-2000-1", "CVE-2026-1"}


def test_une_fois_l_import_complet_termine_les_jeux_json_ne_sont_plus_charges(session_factory, catalog):
    SqlSyncStateStore(session_factory).save(SyncState(full_import_completed_at=datetime.now(timezone.utc)))

    def must_not_load(path):
        raise AssertionError("JSON datasets must not be loaded")

    assert isinstance(workspace_cve_catalog(1, session_factory, load_dataset=must_not_load), SqlCveCatalog)
