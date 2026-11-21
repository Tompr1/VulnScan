import pytest

from app.scanner.budget import ScanBudget
from app.scanner.profile import WEB_AUTH_PLUGIN_ID, ScanProfile
from app.scanner.target import ScanType

BUDGET = ScanBudget(total_seconds=900, reserve_seconds=30, min_plugin_seconds=5, max_plugin_share=0.2)


def test_le_temps_restant_deduit_la_reserve_de_post_traitement():
    assert BUDGET.remaining(elapsed=100) == 770


def test_le_budget_est_epuise_quand_il_reste_5_secondes_ou_moins():
    assert BUDGET.is_exhausted(elapsed=865)
    assert not BUDGET.is_exhausted(elapsed=864)


def test_un_plugin_garde_son_propre_timeout_quand_le_budget_le_permet():
    assert BUDGET.plugin_timeout(30, ScanType.INTERNAL, elapsed=0) == 30


def test_un_plugin_externe_dispose_d_au_moins_20_secondes():
    assert BUDGET.plugin_timeout(10, ScanType.EXTERNAL, elapsed=0) == 20


def test_un_plugin_ne_peut_pas_consommer_plus_de_20_pourcent_du_budget():
    assert BUDGET.plugin_timeout(500, ScanType.INTERNAL, elapsed=0) == 180


def test_le_timeout_d_un_plugin_est_borne_par_le_temps_restant():
    assert BUDGET.plugin_timeout(30, ScanType.INTERNAL, elapsed=850) == 20


def test_le_plugin_dispose_d_une_marge_avant_d_etre_interrompu():
    assert ScanBudget(total_seconds=60, kill_grace_seconds=5).kill_timeout(10) == 15


@pytest.mark.parametrize("invalid", [{"total_seconds": 0}, {"total_seconds": 60, "max_plugin_share": 0}])
def test_un_budget_incoherent_est_refuse(invalid):
    with pytest.raises(ValueError):
        ScanBudget(**invalid)


def test_un_profil_est_lu_depuis_ses_colonnes_json():
    profile = ScanProfile.from_json('{"web.headers": 1, "net.ports": false}', '{"asset": {"criticality": 4}}')

    assert profile.plugin_selection == {"web.headers": True, "net.ports": False}
    assert profile.options == {"asset": {"criticality": 4}}


@pytest.mark.parametrize("text", [None, "", "{not json", "[1, 2]"])
def test_un_json_de_profil_illisible_donne_un_profil_vide(text):
    assert ScanProfile.from_json(text, text) == ScanProfile()


def test_une_authentification_web_par_job_active_le_plugin_et_remplace_celle_du_profil():
    # Arrange
    profile = ScanProfile(plugin_selection={WEB_AUTH_PLUGIN_ID: False}, options={"web_auth": {"type": "basic"}, "x": 1})
    override = {"type": "bearer", "credential_id": 7}

    # Act
    result = profile.with_web_auth(override)

    # Assert
    assert result.plugin_selection[WEB_AUTH_PLUGIN_ID] is True
    assert result.options == {"web_auth": override, "x": 1}
    assert profile.options["web_auth"] == {"type": "basic"}, "the original profile is immutable"


@pytest.mark.parametrize("override", [None, {}, {"credential_id": 3}])
def test_une_authentification_web_sans_type_est_ignoree(override):
    profile = ScanProfile(options={"a": 1})

    assert profile.with_web_auth(override) is profile
