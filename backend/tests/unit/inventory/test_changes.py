from datetime import datetime, timezone

from app.inventory.changes import ChangeKind, DeviceChange, diff_device, diff_inventory
from app.inventory.domain import Device, InstalledApp, InventorySnapshot, Platform
from app.inventory.sync import InventorySync


def device(external_id="d1", os_version="10.0.22631.4317", apps=(), name="PC-01"):
    return Device(external_id, name, Platform.WINDOWS, os_name="Windows", os_version=os_version,
                  apps=tuple(InstalledApp(n, v) for n, v in apps))


def kinds(changes):
    return [(c.kind, c.subject, c.before, c.after) for c in changes]


def test_un_nouvel_appareil_n_enregistre_que_son_enrolement_pas_ses_logiciels():
    changes = diff_device(None, device(apps=[("Chrome", "128"), ("7-Zip", "24.08")]))

    assert kinds(changes) == [(ChangeKind.DEVICE_ENROLLED, "PC-01", None, None)]


def test_un_appareil_inchange_ne_produit_aucun_changement():
    assert diff_device(device(apps=[("Chrome", "128")]), device(apps=[("Chrome", "128")])) == []


def test_une_mise_a_jour_de_l_os_est_journalisee_avec_l_ancienne_et_la_nouvelle_version():
    changes = diff_device(device(os_version="10.0.22631.4317"), device(os_version="10.0.22631.4460"))

    assert kinds(changes) == [(ChangeKind.OS_UPDATED, "Windows", "10.0.22631.4317", "10.0.22631.4460")]


def test_une_mise_a_jour_d_application_est_journalisee_comme_telle():
    changes = diff_device(device(apps=[("Google Chrome", "127.0")]), device(apps=[("Google Chrome", "128.0")]))

    assert kinds(changes) == [(ChangeKind.APP_UPDATED, "Google Chrome", "127.0", "128.0")]


def test_installations_et_suppressions_sont_journalisees():
    changes = diff_device(device(apps=[("VLC", "3.0.20")]), device(apps=[("Zoom", "6.2")]))

    assert kinds(changes) == [(ChangeKind.APP_REMOVED, "VLC", "3.0.20", None), (ChangeKind.APP_INSTALLED, "Zoom", None, "6.2")]


def test_un_nom_d_application_qui_change_de_casse_n_est_pas_un_changement():
    assert diff_device(device(apps=[("7-zip", "24.08")]), device(apps=[("7-Zip", "24.08")])) == []


def test_une_version_ajoutee_a_cote_d_une_autre_est_une_installation():
    # Several Visual C++ runtimes live side by side: not an update.
    before = device(apps=[("Microsoft Visual C++ 2015-2022", "14.38")])
    after = device(apps=[("Microsoft Visual C++ 2015-2022", "14.38"), ("Microsoft Visual C++ 2015-2022", "14.40")])

    assert kinds(diff_device(before, after)) == [(ChangeKind.APP_INSTALLED, "Microsoft Visual C++ 2015-2022", None, "14.40")]


def test_un_appareil_disparu_est_journalise_comme_retire():
    changes = diff_inventory({"d1": device("d1"), "d2": device("d2", name="PC-02")}, [device("d1")])

    assert kinds(changes) == [(ChangeKind.DEVICE_REMOVED, "PC-02", None, None)]


class InMemoryInventory:
    def __init__(self, devices=None):
        self.devices = dict(devices or {})
        self.saved = []

    def active_devices(self, connection_id):
        return self.devices

    def save_snapshot(self, connection_id, workspace_id, snapshot, changes):
        self.saved.append((connection_id, workspace_id, snapshot, list(changes)))


def test_la_synchronisation_enregistre_l_inventaire_et_resume_ce_qui_a_change():
    # Arrange
    repository = InMemoryInventory({"d1": device("d1", apps=[("Chrome", "127")]), "gone": device("gone", name="OLD")})
    snapshot = InventorySnapshot("intune", (device("d1", apps=[("Chrome", "128")]), device("new", name="NEW")),
                                 datetime(2026, 11, 21, tzinfo=timezone.utc), skipped_devices=1)

    # Act
    result = InventorySync(repository).apply(connection_id=3, workspace_id=1, snapshot=snapshot)

    # Assert
    _, _, saved_snapshot, changes = repository.saved[0]
    assert saved_snapshot is snapshot
    assert {c.kind for c in changes} == {ChangeKind.APP_UPDATED, ChangeKind.DEVICE_ENROLLED, ChangeKind.DEVICE_REMOVED}
    assert (result.devices, result.apps, result.enrolled, result.removed, result.changes) == (2, 1, 1, 1, 3)
    assert result.summary() == "2 devices, 1 apps, 1 enrolled, 1 removed, 3 changes, 1 invalid records skipped"


def test_un_changement_reference_l_appareil_par_son_identifiant_source():
    assert DeviceChange("abc", ChangeKind.APP_REMOVED, "VLC").device_external_id == "abc"
