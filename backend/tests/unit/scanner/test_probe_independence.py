"""
Les plugins doivent pouvoir tourner sur une sonde installée chez un client,
sans base de données ni clé de chiffrement de la plateforme : ni eux ni les
modules qu'ils importent (même à l'intérieur d'une fonction) ne touchent à
la base, au chiffrement ou aux catalogues CVE stockés en base.

Ils passent par ``ctx.resources`` (voir ``app.scanner.resources``).
"""
import ast
from pathlib import Path

import pytest

from app.scanner.plugins.loader import BUILTIN_PLUGIN_MODULES

APP_ROOT = Path(__file__).resolve().parents[3] / "app"

FORBIDDEN = (
    "sqlalchemy",
    "app.db",
    "app.core.crypto",
    "app.cve.catalogs",
    "app.cve.reference_datasets",
    "app.cve.sql_catalog",
)


def _source_of(module: str, root: Path) -> Path | None:
    parts = module.split(".")[1:]
    if not parts:
        return root / "__init__.py" if (root / "__init__.py").is_file() else None
    relative = Path(*parts)
    for candidate in (root / relative.with_suffix(".py"), root / relative / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _imports_of(module: str, path: Path) -> set[str]:
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = package.rsplit(".", node.level - 1)[0] if node.level > 1 else package
                base = f"{parent}.{base}" if base else parent
            names.add(base)
            # "from app.scanner import x" may import the module app.scanner.x
            names.update(f"{base}.{alias.name}" for alias in node.names)
    return names


def _import_chains(start: str, root: Path = APP_ROOT) -> dict[str, list[str]]:
    """Every module reachable from ``start``, with the import chain to it."""
    chains = {start: [start]}
    pending = [start]
    while pending:
        module = pending.pop()
        path = _source_of(module, root)
        if path is None:
            continue
        for imported in _imports_of(module, path):
            is_app_module = imported.startswith("app.") and _source_of(imported, root) is not None
            if imported in chains or not (is_app_module or imported.startswith(FORBIDDEN)):
                continue
            chains[imported] = chains[module] + [imported]
            if is_app_module:
                pending.append(imported)
    return chains


def _forbidden(module: str) -> bool:
    return any(module == f or module.startswith(f + ".") for f in FORBIDDEN)


@pytest.mark.parametrize("plugin_module", BUILTIN_PLUGIN_MODULES)
def test_un_plugin_ne_depend_ni_de_la_base_ni_du_chiffrement(plugin_module):
    chains = _import_chains(f"app.scanner.plugins.{plugin_module}")

    violations = [" -> ".join(chain) for module, chain in chains.items() if _forbidden(module)]

    assert violations == []


def test_le_controle_voit_un_import_de_la_base_fait_dans_une_fonction_d_un_module_importe(tmp_path):
    # Garde-fou du test lui-même : la chaîne plugin -> helper -> import différé est suivie.
    plugins = tmp_path / "scanner" / "plugins"
    plugins.mkdir(parents=True)
    (plugins / "fake.py").write_text("from app.scanner import helper\n")
    (tmp_path / "scanner" / "helper.py").write_text("def f():\n    from app.db.session import SessionLocal\n")

    chains = _import_chains("app.scanner.plugins.fake", root=tmp_path)

    assert chains["app.db.session"] == [
        "app.scanner.plugins.fake", "app.scanner.helper", "app.db.session",
    ]


# La moitié « exécution » d'un job (ce que fera la sonde) : recevoir une
# affectation, lancer le bon exécuteur, rendre compte de la progression et
# renvoyer un rapport.
EXECUTION_SIDE = (
    "app.scan_jobs.execution", "app.scan_jobs.assignment", "app.scan_jobs.progress",
    # L'agent de la sonde tout entier, commande comprise.
    "app.probe_agent.cli", "app.probe_agent.agent", "app.probe_agent.reference",
)


@pytest.mark.parametrize("module", EXECUTION_SIDE)
def test_l_execution_d_un_job_ne_depend_ni_de_la_base_ni_du_chiffrement(module):
    chains = _import_chains(module)

    violations = [" -> ".join(chain) for name, chain in chains.items() if _forbidden(name)]

    assert violations == []


# Paquets de requirements-probe.txt → modules qu'ils fournissent.
_MODULES_OF_PACKAGE = {"paho-mqtt": "paho", "pyyaml": "yaml"}
_PROBE_REQUIREMENTS = APP_ROOT.parent / "requirements-probe.txt"


def _probe_packages() -> set[str]:
    names = set()
    for line in _PROBE_REQUIREMENTS.read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            package = line.split("==")[0].split(">=")[0].split("[")[0].strip().lower()
            names.add(_MODULES_OF_PACKAGE.get(package, package.replace("-", "_")))
    return names


def _third_party_imports(starts, root: Path = APP_ROOT) -> dict[str, str]:
    """Paquets tiers importés (même dans une fonction) par ces modules et
    tout le code de l'application qu'ils importent → un module qui l'importe."""
    import sys

    found: dict[str, str] = {}
    for start in starts:
        for module in _import_chains(start, root):
            path = _source_of(module, root)
            if path is None:
                continue
            for imported in _imports_of(module, path):
                top = imported.split(".")[0]
                if top and top != "app" and top not in sys.stdlib_module_names:
                    found.setdefault(top, module)
    return found


def test_l_image_de_la_sonde_contient_tous_les_paquets_que_son_code_importe():
    probe_side = (
        ["app.probe_agent.cli", "app.scanner.plugins.api_scanner", "app.scanner.plugins.iac_scanner"]
        + [f"app.scanner.plugins.{m}" for m in BUILTIN_PLUGIN_MODULES]
    )

    missing = {top: module for top, module in _third_party_imports(probe_side).items() if top not in _probe_packages()}

    assert missing == {}, f"à ajouter à requirements-probe.txt : {missing}"
