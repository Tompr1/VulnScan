import pytest

from app.scanner.plugins.loader import PluginRegistry
from tests.fakes import FakePlugin, meta


def registry(*metas) -> PluginRegistry:
    return PluginRegistry(FakePlugin(m) for m in metas)


def test_un_plugin_s_execute_apres_ses_dependances():
    plugins = registry(meta("c", depends_on=["b"]), meta("b", depends_on=["a"]), meta("a"))

    assert plugins.execution_order() == ["a", "b", "c"]


def test_une_dependance_souple_impose_l_ordre_d_execution():
    plugins = registry(meta("consumer", soft_depends_on=["producer"]), meta("producer"))

    assert plugins.execution_order() == ["producer", "consumer"]


def test_une_dependance_vers_un_plugin_inconnu_est_ignoree():
    plugins = registry(meta("a", depends_on=["missing"]))

    assert plugins.execution_order() == ["a"]


def test_les_plugins_en_cycle_sont_executes_en_dernier():
    plugins = registry(meta("x", depends_on=["y"]), meta("y", depends_on=["x"]), meta("free"))

    assert plugins.execution_order() == ["free", "x", "y"]


def test_une_dependance_a_la_fois_dure_et_souple_ne_bloque_pas_le_tri():
    plugins = registry(meta("b", depends_on=["a"], soft_depends_on=["a"]), meta("a"))

    assert plugins.execution_order() == ["a", "b"]


def test_deux_plugins_ne_peuvent_pas_avoir_le_meme_identifiant():
    with pytest.raises(ValueError, match="Duplicate plugin id"):
        registry(meta("dup"), meta("dup"))


def test_sans_selection_seuls_les_plugins_actifs_par_defaut_sont_executes():
    plugins = registry(meta("on"), meta("off", enabled_by_default=False))

    assert plugins.resolve_enabled({}) == ["on"]


def test_la_selection_du_profil_prime_sur_le_reglage_par_defaut():
    plugins = registry(meta("on"), meta("off", enabled_by_default=False))

    assert plugins.resolve_enabled({"on": False, "off": True}) == ["off"]


def test_un_plugin_absent_d_un_profil_existant_garde_son_reglage_par_defaut():
    plugins = registry(meta("old"), meta("new_plugin"))

    assert plugins.resolve_enabled({"old": True}) == ["old", "new_plugin"]


def test_activer_un_plugin_active_ses_dependances_dures_transitivement():
    plugins = registry(
        meta("a", enabled_by_default=False),
        meta("b", depends_on=["a"], enabled_by_default=False),
        meta("c", depends_on=["b"], enabled_by_default=False),
    )

    assert plugins.resolve_enabled({"c": True}) == ["a", "b", "c"]


def test_une_dependance_souple_n_est_pas_activee_automatiquement():
    plugins = registry(meta("opt", enabled_by_default=False), meta("main", soft_depends_on=["opt"]))

    assert plugins.resolve_enabled({}) == ["main"]


def test_un_module_qui_ne_respecte_pas_le_contrat_plugin_est_ignore():
    # "base" has no META/Check and "does_not_exist" cannot be imported.
    plugins = PluginRegistry.discover(["base", "does_not_exist", "redis_noauth"])

    assert [p.meta.plugin_id for p in plugins] == ["infra.redis.deep"]


def test_un_plugin_fournit_des_valeurs_de_repli_pour_ses_artefacts():
    plugin_meta = meta("p", provides=["count", "items"], artifact_defaults={"count": 0})

    fallback = plugin_meta.fallback_artifacts()

    assert fallback == {"count": 0, "items": []}
    assert fallback["items"] is not plugin_meta.fallback_artifacts()["items"], "each call returns fresh values"
