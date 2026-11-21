from datetime import timezone

import pytest
from pydantic import ValidationError

from app.api.schemas.scan import CreateJobRequest, CreateProfileRequest, CreateScheduleRequest, UpdateProfileRequest


def error_fields(exc: ValidationError) -> set[str]:
    return {".".join(str(p) for p in error["loc"]) for error in exc.errors()}


def test_une_demande_de_scan_valide_est_lue_avec_ses_valeurs_par_defaut():
    request = CreateJobRequest(target=" https://app.local ", profile_id="3")

    assert (request.target, request.profile_id, request.scan_type, request.web_auth) == ("https://app.local", 3, "internal", None)


def test_toutes_les_erreurs_d_une_demande_de_scan_sont_signalees_ensemble():
    with pytest.raises(ValidationError) as exc:
        CreateJobRequest(target="", profile_id=0, scan_type="everything", asset_id="abc")

    assert error_fields(exc.value) == {"target", "profile_id", "scan_type", "asset_id"}


def test_une_cible_sans_hote_est_refusee_a_l_entree_de_l_api():
    with pytest.raises(ValidationError, match="does not contain a host"):
        CreateJobRequest(target="http://", profile_id=1)


def test_un_type_d_authentification_web_inconnu_est_refuse():
    with pytest.raises(ValidationError) as exc:
        CreateJobRequest(target="app.local", profile_id=1, web_auth={"type": "kerberos"})

    assert error_fields(exc.value) == {"web_auth.type"}


def test_les_champs_propres_a_chaque_authentification_web_sont_conserves():
    request = CreateJobRequest(target="app.local", profile_id=1, web_auth={"type": "form", "login_url": "/login"})

    assert request.job_meta() == {"web_auth": {"type": "form", "login_url": "/login"}}


def test_un_identifiant_ephemere_n_est_supprime_que_s_il_est_reference():
    with_credential = CreateJobRequest(target="a.local", profile_id=1, web_auth={"type": "basic", "credential_id": 4}, web_auth_credential_ephemeral=True)
    without_credential = CreateJobRequest(target="a.local", profile_id=1, web_auth={"type": "basic"}, web_auth_credential_ephemeral=True)

    assert with_credential.job_meta()["web_auth_credential_ephemeral"] is True
    assert "web_auth_credential_ephemeral" not in without_credential.job_meta()


@pytest.mark.parametrize("selection", ['{"web.headers": true}', {"web.headers": True}])
def test_un_profil_accepte_sa_selection_en_objet_ou_en_texte_json(selection):
    request = CreateProfileRequest(name="Web", plugin_selection_json=selection)

    assert request.plugin_selection_text() == '{"web.headers": true}'


@pytest.mark.parametrize("options", ["{broken", "[1, 2]"])
def test_des_options_de_profil_qui_ne_sont_pas_un_objet_json_sont_refusees(options):
    with pytest.raises(ValidationError, match="options_json"):
        CreateProfileRequest(options_json=options)


def test_une_mise_a_jour_de_profil_ne_concerne_que_les_champs_envoyes():
    request = UpdateProfileRequest(name="Renamed")

    assert request.model_fields_set == {"name"}


def test_une_planification_ponctuelle_exige_une_date():
    with pytest.raises(ValidationError, match="custom_datetime is required"):
        CreateScheduleRequest(target="a.local", profile_id=1, schedule_type="custom")


def test_une_date_de_planification_sans_fuseau_est_consideree_en_utc():
    request = CreateScheduleRequest(target="a.local", profile_id=1, schedule_type="custom", custom_datetime="2026-03-10T14:30:00")

    assert request.custom_datetime.tzinfo == timezone.utc


def test_un_intervalle_de_planification_nul_est_refuse():
    with pytest.raises(ValidationError):
        CreateScheduleRequest(target="a.local", profile_id=1, interval_hours=0)
