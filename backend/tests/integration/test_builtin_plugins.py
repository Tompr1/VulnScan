"""
Contract tests of the built-in plugins: every module listed in the registry
loads and respects the plugin contract. A plugin that fails to import is
skipped at runtime with a warning — this suite makes that a test failure.
"""
import pytest

from app.scanner.plugins.loader import BUILTIN_PLUGIN_MODULES, builtin_registry

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def plugins():
    return builtin_registry()


def test_chaque_module_de_plugin_declare_est_charge(plugins):
    assert len(plugins) == len(BUILTIN_PLUGIN_MODULES)


def test_chaque_dependance_dure_designe_un_plugin_existant(plugins):
    missing = {
        (plugin.meta.plugin_id, dependency)
        for plugin in plugins
        for dependency in plugin.meta.depends_on
        if dependency not in plugins
    }

    assert missing == set()


def test_l_ordre_d_execution_respecte_toutes_les_dependances(plugins):
    position = {plugin_id: index for index, plugin_id in enumerate(plugins.execution_order())}

    late = [
        (plugin.meta.plugin_id, dependency)
        for plugin in plugins
        for dependency in plugin.meta.ordering_dependencies
        if dependency in position and position[dependency] > position[plugin.meta.plugin_id]
    ]

    assert late == []


def test_les_valeurs_de_repli_ne_concernent_que_des_artefacts_fournis(plugins):
    undeclared = {
        (plugin.meta.plugin_id, key)
        for plugin in plugins
        for key in plugin.meta.artifact_defaults
        if key not in plugin.meta.provides
    }

    assert undeclared == set()


def test_chaque_plugin_a_un_timeout_positif(plugins):
    assert all(plugin.meta.timeout_seconds > 0 for plugin in plugins)
