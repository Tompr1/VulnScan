import json
from datetime import datetime, timedelta, timezone

import pytest

from app.cve.nvd import NvdPage, parse_vulnerability
from app.cve.nvd_sync import HttpNvdFeed, NvdCatalogSync, SyncState, modified_windows
from tests.fakes import FakeClock
from tests.unit.cve.nvd_fixtures import nvd_entry, page

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FakeNvdFeed:
    """Serves a fixed list of CVEs, paged like the NVD API; records requests."""

    def __init__(self, cves, error_at_index=None):
        self.cves = cves
        self.requests = []
        self._error_at_index = error_at_index

    def fetch(self, start_index, page_size, modified=None):
        self.requests.append((start_index, modified))
        if start_index == self._error_at_index:
            raise ConnectionError("NVD unavailable")
        selected = [c for c in self.cves if not modified or modified[0] <= c.last_modified_at <= modified[1]]
        chunk = selected[start_index:start_index + page_size]
        return NvdPage(start_index, len(selected), tuple(chunk), len(chunk))


class InMemoryCveStore:
    def __init__(self):
        self.cves = {}

    def upsert(self, cves):
        self.cves.update({c.record.cve_id: c for c in cves})


class InMemoryStates:
    def __init__(self, state=None):
        self.state = state or SyncState()
        self.saves = 0

    def load(self):
        return self.state

    def save(self, state):
        self.state = state
        self.saves += 1


def cves(count, modified=T0):
    return [parse_vulnerability(nvd_entry(f"CVE-2026-{i:05d}", modified=modified.isoformat())) for i in range(count)]


def make_sync(feed, store=None, states=None, clock=None, budget=1000.0, page_size=2):
    clock = clock or FakeClock()
    return NvdCatalogSync(
        feed, store or InMemoryCveStore(), states or InMemoryStates(),
        page_size=page_size, budget_seconds=budget, clock=clock.utc_now, monotonic=clock.monotonic,
    )


def test_l_import_complet_charge_toutes_les_cve_page_par_page():
    # Arrange
    store, states = InMemoryCveStore(), InMemoryStates()
    feed = FakeNvdFeed(cves(5))

    # Act
    report = make_sync(feed, store, states).run()

    # Assert
    assert report.complete and (report.mode, report.pages, report.cves) == ("full", 3, 5)
    assert len(store.cves) == 5
    assert [index for index, _ in feed.requests] == [0, 2, 4]


def test_a_la_fin_de_l_import_les_changements_sont_suivis_depuis_son_debut():
    # Arrange: the import takes time, during which NVD keeps changing
    clock, states = FakeClock(), InMemoryStates()
    started = clock.utc
    feed = FakeNvdFeed(cves(3))
    original_fetch = feed.fetch
    feed.fetch = lambda *args: (clock.advance(3600), original_fetch(*args))[1]

    # Act
    make_sync(feed, states=states, clock=clock, budget=100_000).run()

    # Assert: the next incremental run starts when the import STARTED, not when it ended
    assert states.state.full_import_done
    assert states.state.synced_until == started < states.state.full_import_completed_at


def test_un_import_interrompu_par_son_budget_reprend_a_la_page_suivante():
    # Arrange: each page "takes" 10 s of a 15 s budget
    clock, states, store = FakeClock(), InMemoryStates(), InMemoryCveStore()
    feed = FakeNvdFeed(cves(6))
    original_fetch = feed.fetch

    def slow_fetch(*args):
        clock.advance(10)
        return original_fetch(*args)

    feed.fetch = slow_fetch

    # Act
    first = make_sync(feed, store, states, clock, budget=15).run()
    second = make_sync(feed, store, states, clock, budget=1000).run()

    # Assert
    assert not first.complete and first.pages == 2
    assert second.complete
    assert [index for index, _ in feed.requests] == [0, 2, 4], "no page is downloaded twice"
    assert len(store.cves) == 6


def test_une_erreur_nvd_conserve_la_progression_deja_faite():
    states = InMemoryStates()

    with pytest.raises(ConnectionError):
        make_sync(FakeNvdFeed(cves(6), error_at_index=4), states=states).run()

    assert states.state.full_import_next_index == 4
    assert not states.state.full_import_done


def test_un_nvd_vide_termine_l_import_immediatement():
    assert make_sync(FakeNvdFeed([])).run().complete


def test_la_mise_a_jour_incrementale_ne_demande_que_les_cve_modifiees_depuis_la_derniere_synchro():
    # Arrange
    clock = FakeClock()
    synced_until = clock.utc - timedelta(days=2)
    states = InMemoryStates(SyncState(full_import_completed_at=synced_until, synced_until=synced_until))
    feed = FakeNvdFeed(cves(1, modified=synced_until - timedelta(days=10)) + cves(3, modified=clock.utc - timedelta(days=1)))

    # Act
    report = make_sync(feed, states=states, clock=clock).run()

    # Assert
    assert report.mode == "incremental" and report.complete and report.cves == 3
    assert {window for _, window in feed.requests} == {(synced_until, clock.utc)}
    assert states.state.synced_until == clock.utc


def test_une_longue_absence_est_rattrapee_par_fenetres_de_120_jours():
    clock = FakeClock()
    last = clock.utc - timedelta(days=300)
    states = InMemoryStates(SyncState(full_import_completed_at=last, synced_until=last))
    feed = FakeNvdFeed([])

    make_sync(feed, states=states, clock=clock).run()

    windows = [window for _, window in feed.requests]
    assert [round((end - start).days) for start, end in windows] == [120, 120, 60]
    assert windows[0][0] == last and windows[-1][1] == clock.utc


def test_les_fenetres_de_modification_couvrent_exactement_la_periode():
    windows = list(modified_windows(T0, T0 + timedelta(days=250), timedelta(days=120)))

    assert windows == [(T0, T0 + timedelta(days=120)), (T0 + timedelta(days=120), T0 + timedelta(days=240)),
                       (T0 + timedelta(days=240), T0 + timedelta(days=250))]


@pytest.mark.parametrize("size", [0, 2001])
def test_une_taille_de_page_hors_des_limites_nvd_est_refusee(size):
    with pytest.raises(ValueError):
        make_sync(FakeNvdFeed([]), page_size=size)


def test_le_flux_http_envoie_la_cle_et_la_fenetre_au_format_nvd():
    # Arrange
    calls = []

    def fetch_url(url, headers):
        calls.append((url, dict(headers)))
        return json.dumps(page([nvd_entry("CVE-2026-9")], start_index=200, total=201)).encode()

    feed = HttpNvdFeed(fetch_url, api_key="secret-key")

    # Act
    result = feed.fetch(200, 100, (T0, T0 + timedelta(days=1, hours=2)))

    # Assert
    url, headers = calls[0]
    assert url == ("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=200&resultsPerPage=100"
                   "&lastModStartDate=2026-01-01T00:00:00.000&lastModEndDate=2026-01-02T02:00:00.000")
    assert headers["apiKey"] == "secret-key"
    assert [c.record.cve_id for c in result.cves] == ["CVE-2026-9"]


def test_sans_cle_le_flux_http_n_envoie_pas_d_en_tete_apikey():
    calls = []
    HttpNvdFeed(lambda url, headers: calls.append(dict(headers)) or json.dumps(page([])).encode()).fetch(0, 10)

    assert "apiKey" not in calls[0]
