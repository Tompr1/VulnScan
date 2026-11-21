from datetime import datetime, timezone

import pytest

from app.inventory.domain import Device, InstalledApp, Platform


@pytest.mark.parametrize(
    ("os_name", "platform"),
    [
        ("Windows", Platform.WINDOWS),
        ("macOS", Platform.MACOS),
        ("iOS", Platform.IOS),
        ("iPadOS", Platform.IOS),
        ("Android", Platform.ANDROID),
        ("AndroidForWork", Platform.ANDROID),
        ("Linux", Platform.LINUX),
        ("Ubuntu", Platform.LINUX),
        ("ChromeOS", Platform.OTHER),
        (None, Platform.OTHER),
    ],
)
def test_le_systeme_annonce_par_le_gestionnaire_est_range_dans_une_plateforme(os_name, platform):
    assert Platform.from_os_name(os_name) is platform


def test_une_application_est_normalisee_a_la_creation():
    app = InstalledApp("  Mozilla Firefox (x64 fr) ", " 128.0.3 ", "")

    assert (app.name, app.version, app.publisher, app.key) == ("Mozilla Firefox (x64 fr)", "128.0.3", None, "mozilla firefox (x64 fr)")


@pytest.mark.parametrize("name", ["", "   ", None])
def test_une_application_sans_nom_est_refusee(name):
    with pytest.raises(ValueError):
        InstalledApp(name)


@pytest.mark.parametrize(("external_id", "name"), [("", "PC-01"), ("abc", " ")])
def test_un_appareil_sans_identifiant_ou_sans_nom_est_refuse(external_id, name):
    with pytest.raises(ValueError):
        Device(external_id, name, Platform.WINDOWS)


def test_une_date_de_synchronisation_sans_fuseau_est_refusee():
    with pytest.raises(ValueError, match="timezone"):
        Device("abc", "PC-01", Platform.WINDOWS, last_check_in_at=datetime(2026, 1, 1))


def test_un_appareil_valide_porte_ses_applications():
    device = Device("abc", "PC-01", Platform.WINDOWS, last_check_in_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    apps=(InstalledApp("7-Zip", "24.08"),))

    assert device.apps[0].name == "7-Zip"
