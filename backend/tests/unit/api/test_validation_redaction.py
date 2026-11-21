from app.api.validation import REDACTED, redact_errors


def test_la_valeur_d_un_champ_sensible_rejete_n_est_jamais_renvoyee():
    errors = redact_errors([{"loc": ("body", "client_secret"), "msg": "too short", "input": "court"}])

    assert errors[0]["input"] == REDACTED
    assert errors[0]["msg"] == "too short"


def test_un_corps_complet_renvoye_en_erreur_est_caviarde_en_profondeur():
    body = {"name": "x", "auth": {"password": "p4ss", "user": "bob"}, "items": [{"api_key": "k"}]}

    errors = redact_errors([{"loc": ("body",), "msg": "invalid", "input": body}])

    assert errors[0]["input"] == {"name": "x", "auth": {"password": REDACTED, "user": "bob"}, "items": [{"api_key": REDACTED}]}


def test_un_champ_ordinaire_garde_sa_valeur_pour_aider_l_utilisateur():
    errors = redact_errors([{"loc": ("body", "tenant_id"), "msg": "invalid uuid", "input": "pas-un-uuid"}])

    assert errors[0]["input"] == "pas-un-uuid"
