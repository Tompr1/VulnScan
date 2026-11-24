"""
Isolation entre clients (workspaces) sur toute l'API HTTP.

Un client « voisin » (workspace 2) possède un objet de chaque type, tous
marqués « voisin ». Un admin du workspace 1 appelle chaque route de l'API en
visant les identifiants du voisin, puis on vérifie que :
- aucune réponse ne contient la marque du voisin ;
- aucune donnée du voisin n'a changé ;
- aucune donnée hors du voisin ne référence ni ne recopie une donnée du voisin.

Les routes sont découvertes depuis l'application : une nouvelle route est
couverte d'office, et un paramètre de chemin inconnu fait échouer le test
jusqu'à ce qu'on lui associe un objet du voisin.

Filet de sécurité de la phase 0 de l'interface MSP : il doit rester vert
pendant toute la migration vers le multi-clients.
"""
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import or_, select

from app.api import (
    routes_ai, routes_analytics, routes_api_scanner, routes_assets, routes_auth, routes_credentials,
    routes_datasets, routes_events, routes_graph, routes_iac_scanner, routes_integrations,
    routes_inventory, routes_reports, routes_scan, routes_settings, routes_threat_intel, routes_web_auth,
)
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.config import settings
from app.core.crypto import encrypt_str
from app.core.job_queue import get_job_queue
from app.db import models
from app.db.session import Base
from app.graph import neo4j_client
from app.inventory.repository import SqlInventoryReadModel
from app.scanner.cancellation import NeverCancelled
from tests.fakes import SpyJobQueue

pytestmark = pytest.mark.integration

MARQUE = "voisin"
CIBLE_DU_VOISIN = "srv.voisin.example"
CLIENT, VOISIN = 1, 2

ROUTERS = [
    routes_auth, routes_credentials, routes_datasets, routes_scan, routes_settings, routes_graph,
    routes_integrations, routes_ai, routes_api_scanner, routes_iac_scanner, routes_web_auth,
    routes_threat_intel, routes_assets, routes_reports, routes_events, routes_analytics, routes_inventory,
]


@dataclass(frozen=True)
class Ids:
    """Identifiants fixes des objets du voisin (et de quelques objets du client)."""
    profil: int = 6  # créé par la fixture `workspace` de conftest
    profil_client: int = 5
    utilisateur: int = 901
    credential: int = 902
    dataset: int = 903
    asset: int = 904
    job: int = 905
    finding: int = 906
    planification: int = 907
    modele_rapport: int = 908
    fournisseur_ia: int = 909
    analyse_ia: int = 910
    connexion: int = 911
    appareil: int = 912
    asset_client: int = 101
    job_client: int = 102
    fournisseur_ia_client: int = 103
    credential_client: int = 104


V = Ids()

# Paramètres de chemin → objet du voisin visé.
VALEURS_DE_CHEMIN = {
    "cred_id": V.credential,
    "ds_id": V.dataset,
    "kind": "cisa_kev",
    "profile_id": V.profil,
    "job_id": V.job,
    "sched_id": V.planification,
    "user_id": V.utilisateur,
    "provider": "slack",
    "provider_id": V.fournisseur_ia,
    "analysis_id": V.analyse_ia,
    "asset_id": V.asset,
    "tpl_id": V.modele_rapport,
    "connection_id": V.connexion,
    "device_id": V.appareil,
    "client_id": VOISIN,
    "target": CIBLE_DU_VOISIN,
}

# Paramètres de requête → objet du voisin visé.
VALEURS_DE_REQUETE = {"job_a": V.job, "job_b": V.job, "template_id": V.modele_rapport}

# Corps valides des routes qui modifient un objet désigné dans le chemin : sans
# eux, la validation (422) répondrait avant le contrôle d'appartenance.
CORPS = {
    ("PUT", "/credentials/{cred_id}"): {"name": "pirate"},
    ("PATCH", "/datasets/{ds_id}"): {"name": "pirate"},
    ("PUT", "/scan/profiles/{profile_id}"): {"name": "pirate"},
    ("PUT", "/settings/users/{user_id}/password"): {"new_password": "Pirate-1234567!"},
    ("PUT", "/ai/providers/{provider_id}"): {"name": "pirate"},
    ("PATCH", "/assets/{asset_id}"): {"name": "pirate"},
    ("PATCH", "/reports/templates/{tpl_id}"): {"name": "pirate"},
    ("PUT", "/inventory/connections/{connection_id}"): {"name": "pirate"},
    # Sans corps, le test d'intégration relit la configuration enregistrée.
    ("POST", "/integrations/{provider}/test"): None,
}

# Routes sans donnée propre à un client, ou qui sortent du processus.
HORS_PERIMETRE = {
    ("POST", "/auth/login"): "avant authentification, aucun client",
    ("GET", "/scan/plugins"): "catalogue des plugins, commun",
    ("GET", "/settings/update/check"): "mise à jour de la plateforme (appel réseau)",
    ("POST", "/settings/update/trigger"): "mise à jour de la plateforme (écrit dans /data)",
    ("GET", "/settings/update/status"): "mise à jour de la plateforme",
    ("POST", "/scan/web-auth/inspect"): "récupère une page de login externe (réseau)",
    ("POST", "/scan/web-auth/test-login"): "teste un login externe (réseau)",
    ("POST", "/settings/integrations/test"): "teste une destination fournie dans le corps (réseau)",
    ("POST", "/scan/api-scanner/parse"): "analyse un fichier fourni, rien n'est stocké",
    ("POST", "/scan/iac/parse"): "analyse un fichier fourni, rien n'est stocké",
    ("GET", "/scan/api-scanner/checks"): "catalogue des contrôles, commun",
    ("GET", "/scan/iac/kinds"): "catalogue des formats, commun",
    ("GET", "/reports/templates/sections"): "catalogue des sections, commun",
    ("POST", "/analytics/discover"): "résolution DNS d'une cible fournie, rien n'est lu en base",
    ("GET", "/threat-intel/cves/{cve_id}"): "référentiel CVE, commun",
}

# Appels qui désignent un objet du voisin depuis un objet du client (références
# croisées) : ils ne doivent rien créer ni lier au voisin.
APPELS_CROISES = [
    ("POST", "/scan/jobs", {"json": {"target": "10.0.0.1", "profile_id": V.profil}}),
    ("POST", "/scan/jobs", {"json": {"target": "10.0.0.1", "profile_id": V.profil_client, "asset_id": V.asset}}),
    ("POST", "/scan/schedules", {"json": {"target": "10.0.0.1", "profile_id": V.profil}}),
    ("POST", "/assets", {"json": {"name": "a", "parent_id": V.asset}}),
    ("POST", "/assets", {"json": {"name": "b", "default_profile_id": V.profil}}),
    ("POST", "/assets", {"json": {"name": "c", "default_credential_id": V.credential}}),
    ("PATCH", f"/assets/{V.asset_client}", {"json": {"parent_id": V.asset}}),
    ("PATCH", f"/assets/{V.asset_client}", {"json": {"default_profile_id": V.profil}}),
    ("PATCH", f"/assets/{V.asset_client}", {"json": {"default_credential_id": V.credential}}),
    ("POST", "/ai/analyze", {"json": {"job_id": V.job, "provider": "openai_compat"}}),
    ("POST", "/ai/poc", {"json": {"analysis_id": V.analyse_ia, "finding_id": V.finding}}),
    ("POST", "/analytics/reverify", {"json": {"job_id": V.job}}),
    ("GET", f"/reports/{V.job_client}/download", {"params": {"template_id": V.modele_rapport}}),
    ("GET", "/analytics/diff", {"params": {"job_a": V.job_client, "job_b": V.job}}),
    ("GET", "/analytics/compare", {"params": {"job_a": V.job_client, "job_b": V.job}}),
]


# ── Découverte des routes ────────────────────────────────────────────────────

@dataclass(frozen=True)
class Appel:
    methode: str
    modele: str
    chemin: str = ""
    options: dict = field(default_factory=dict)
    parametres_inconnus: tuple = ()

    @property
    def nom(self) -> str:
        return f"{self.methode} {self.chemin or self.modele}"


def routes_de_l_api() -> list[APIRoute]:
    return [route for module in ROUTERS for route in module.router.routes if isinstance(route, APIRoute)]


def appel_vers_le_voisin(route: APIRoute, methode: str) -> Appel:
    chemin, inconnus = route.path, []
    for parametre in route.dependant.path_params:
        valeur = VALEURS_DE_CHEMIN.get(parametre.name)
        if valeur is None:
            inconnus.append(parametre.name)
            continue
        chemin = chemin.replace(f"{{{parametre.name}}}", str(valeur)).replace(f"{{{parametre.name}:path}}", str(valeur))
    options: dict = {}
    requete = {p.name: VALEURS_DE_REQUETE[p.name] for p in route.dependant.query_params if p.name in VALEURS_DE_REQUETE}
    if requete:
        options["params"] = requete
    corps = CORPS.get((methode, route.path), {})
    if methode in ("POST", "PUT", "PATCH") and corps is not None:
        options["json"] = corps
    return Appel(methode, route.path, chemin, options, tuple(inconnus))


def appels_generiques() -> list[Appel]:
    return [
        appel_vers_le_voisin(route, methode)
        for route in routes_de_l_api()
        for methode in sorted(route.methods)
        if (methode, route.path) not in HORS_PERIMETRE
    ]


def appels_croises() -> list[Appel]:
    return [Appel(methode, chemin, chemin, options) for methode, chemin, options in APPELS_CROISES]


# ── Données ──────────────────────────────────────────────────────────────────

@pytest.fixture
def donnees(db, workspace, tmp_path):
    """Un objet de chaque type chez le voisin, et le strict nécessaire chez le client."""
    maintenant = datetime(2026, 11, 1, tzinfo=timezone.utc)
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps([{"cve": "CVE-2099-0001", "vendor": "acme"}]))
    db.add_all([
        models.User(id=V.utilisateur, email="admin@voisin.example", password_hash="x"),
        models.ClientGroup(id=1, name="region-b"),
        models.UserGroup(id=1, name="equipe-b"),
        models.Credential(id=V.credential, workspace_id=VOISIN, name="ssh-voisin", username="root-voisin",
                          secret_enc=encrypt_str("secret-voisin")),
        # Référentiel commun à tous les clients : rien du voisin dedans.
        models.CveDataset(id=V.dataset, name="CISA KEV", kind="cisa_kev", path=str(kev)),
        models.Asset(id=V.asset, workspace_id=VOISIN, name="parc-voisin", owner="dsi@voisin.example"),
        models.Asset(id=V.asset_client, workspace_id=CLIENT, name="parc-client"),
        models.Credential(id=V.credential_client, workspace_id=CLIENT, name="ssh-client", username="root",
                          secret_enc=encrypt_str("secret-client")),
    ])
    db.flush()
    db.add_all([
        models.AccessGrant(user_id=V.utilisateur, workspace_id=VOISIN, role="admin"),
        models.ClientGroupMember(client_group_id=1, workspace_id=VOISIN),
        models.UserGroupMember(user_group_id=1, user_id=V.utilisateur),
        models.ScanJob(id=V.job, workspace_id=VOISIN, target="srv.voisin.example", profile_id=V.profil,
                       asset_id=V.asset, status="done", created_at=maintenant, finished_at=maintenant,
                       meta_json=json.dumps({"note": "voisin"})),
        models.ScanJob(id=V.job_client, workspace_id=CLIENT, target="10.0.0.1", profile_id=V.profil_client,
                       status="done", created_at=maintenant, finished_at=maintenant),
        models.ScanSchedule(id=V.planification, workspace_id=VOISIN, name="hebdo-voisin",
                            target="srv.voisin.example", profile_id=V.profil),
        models.ReportTemplate(id=V.modele_rapport, workspace_id=VOISIN, name="rapport-voisin",
                              options_json=json.dumps({"company": "Voisin SA"})),
        models.Integration(workspace_id=VOISIN, provider="slack", enabled=True,
                           config_json=json.dumps({"webhook_url": "http://127.0.0.1:9/voisin"})),
        models.AiProviderConfig(id=V.fournisseur_ia, workspace_id=VOISIN, provider_type="openai_compat",
                                name="ia-voisin", model="m", api_key_enc=encrypt_str("cle-voisin"),
                                endpoint="http://127.0.0.1:9/voisin"),
        models.AiProviderConfig(id=V.fournisseur_ia_client, workspace_id=CLIENT, provider_type="openai_compat",
                                name="ia-client", model="m", endpoint="http://127.0.0.1:9/client"),
        models.WorkspaceSetting(workspace_id=VOISIN, key="marque", value_json=json.dumps({"client": "voisin"})),
        models.SuppressedFinding(workspace_id=VOISIN, fingerprint="fp-voisin", reason="faux positif voisin"),
        models.AuditLog(workspace_id=VOISIN, actor_email="admin@voisin.example", action="login voisin"),
        models.InventoryConnection(id=V.connexion, workspace_id=VOISIN, name="intune-voisin",
                                   tenant_id="t-voisin", client_id="c-voisin", client_secret_enc=encrypt_str("s-voisin")),
    ])
    db.flush()
    db.add_all([
        models.Finding(id=V.finding, workspace_id=VOISIN, job_id=V.job, target="srv.voisin.example",
                       plugin_id="p", title="faille-voisin", severity="high", fingerprint="fp-voisin",
                       created_at=maintenant),
        models.AiAnalysis(id=V.analyse_ia, workspace_id=VOISIN, job_id=V.job, provider="p", mode="validate",
                          status="done", result_json=json.dumps({"summary": "voisin"})),
        models.InventoryDevice(id=V.appareil, workspace_id=VOISIN, connection_id=V.connexion, external_id="d-1",
                               name="PC-VOISIN", platform="windows", os_name="Windows"),
        models.InventoryAuditRun(connection_id=V.connexion, job_id=V.job, audited_at=maintenant, devices=1, issues=1),
    ])
    db.flush()
    db.add_all([
        models.InventoryDeviceApp(device_id=V.appareil, name="logiciel-voisin", version="1.0"),
        models.InventoryDeviceChange(device_id=V.appareil, kind="app_added", subject="logiciel-voisin",
                                     detected_at=maintenant),
    ])
    db.commit()


@dataclass
class Temoins:
    """Ce que l'API a déclenché hors de la base : files de jobs, connexions Intune."""
    queue: SpyJobQueue = field(default_factory=SpyJobQueue)
    sources_ouvertes: list = field(default_factory=list)

    def ouvrir_source(self, credentials):
        self.sources_ouvertes.append(credentials)
        raise RuntimeError("aucune connexion Intune dans ce test")


@pytest.fixture
def temoins():
    return Temoins()


@pytest.fixture
def client(session_factory, donnees, temoins, session_de, monkeypatch):
    claims = session_de(CLIENT, "admin", email="admin@client.example")
    # Aucun service externe : Redis refuse la connexion, Neo4j est absent.
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:1/0")
    monkeypatch.setattr(neo4j_client.Neo4jClient, "__init__", lambda self: setattr(self, "_driver", None))
    monkeypatch.setattr(routes_graph, "_neo4j", None)

    app = FastAPI()
    install_validation_error_handler(app)
    for module in ROUTERS:
        app.include_router(module.router)

    def test_db():
        with session_factory() as session:
            yield session

    app.dependency_overrides.update({
        get_db: test_db,
        require_auth: lambda: claims,
        get_job_queue: lambda: temoins.queue,
        routes_scan.get_cancellation_signal: NeverCancelled,
        routes_inventory.get_inventory_read_model: lambda: SqlInventoryReadModel(session_factory),
        routes_inventory.get_inventory_source_factory: lambda: temoins.ouvrir_source,
    })
    return TestClient(app, raise_server_exceptions=False)


# ── Photographie de la base ──────────────────────────────────────────────────

def _identifiants_du_voisin(session) -> dict[str, set]:
    """Clés primaires des lignes du voisin, table par table (parents d'abord)."""
    ids: dict[str, set] = {}
    for table in Base.metadata.sorted_tables:
        filtre = _filtre_du_voisin(table, ids)
        if filtre is not None:
            ids[table.name] = set(session.execute(select(table.c.id).where(filtre)).scalars())
    return ids


def _filtre_du_voisin(table, ids):
    if table.name == "workspaces":
        return table.c.id == VOISIN
    if table.name == "users":  # comptes du MSP : ceux qui ouvrent le voisin
        droits = models.AccessGrant.__table__
        return table.c.id.in_(select(droits.c.user_id).where(droits.c.workspace_id == VOISIN))
    if "workspace_id" in table.c:
        return table.c.workspace_id == VOISIN
    liens = [cle.parent.in_(ids[cle.column.table.name]) for cle in table.foreign_keys if cle.column.table.name in ids]
    return or_(*liens) if liens else None


def photographie(session_factory) -> dict:
    with session_factory() as session:
        ids = _identifiants_du_voisin(session)
        lignes = {}
        for table in Base.metadata.sorted_tables:
            if table.name in ids:
                rangees = session.execute(select(table).where(table.c.id.in_(ids[table.name]))).all()
                lignes[table.name] = sorted(tuple(map(repr, r)) for r in rangees)
        return lignes


def fuites_en_base(session_factory) -> list[str]:
    """Lignes hors du voisin qui pointent vers lui ou recopient sa marque."""
    fuites = []
    with session_factory() as session:
        ids = _identifiants_du_voisin(session)
        for table in Base.metadata.sorted_tables:
            requete = select(table)
            if table.name in ids:
                requete = requete.where(table.c.id.not_in(ids[table.name]))
            for ligne in session.execute(requete).mappings():
                for cle in table.foreign_keys:
                    cible = cle.column.table.name
                    if cible in ids and ligne[cle.parent.name] in ids[cible]:
                        fuites.append(f"{table.name}#{ligne['id']}.{cle.parent.name} → {cible}#{ligne[cle.parent.name]}")
                for colonne, valeur in ligne.items():
                    if isinstance(valeur, str) and MARQUE in valeur.lower():
                        fuites.append(f"{table.name}#{ligne['id']}.{colonne} recopie {valeur[:60]!r}")
    return fuites


def _verifier_isolation(client, session_factory, temoins: Temoins, appel: Appel) -> None:
    avant = photographie(session_factory)

    reponse = client.request(appel.methode, appel.chemin, **appel.options)

    exposition = (reponse.text + " ".join(reponse.headers.values())).lower()
    if CIBLE_DU_VOISIN in appel.chemin:  # la route peut renvoyer la cible demandée, rien d'autre
        exposition = exposition.replace(CIBLE_DU_VOISIN, "")
    assert MARQUE not in exposition, f"{appel.nom} → {reponse.status_code} expose le voisin : {reponse.text[:300]}"
    assert photographie(session_factory) == avant, f"{appel.nom} → {reponse.status_code} a modifié le voisin"
    assert fuites_en_base(session_factory) == [], f"{appel.nom} → {reponse.status_code} relie le client au voisin"
    assert V.job not in temoins.queue.scans and V.analyse_ia not in temoins.queue.analyses, (
        f"{appel.nom} a lancé un traitement du voisin"
    )
    assert temoins.sources_ouvertes == [], f"{appel.nom} a ouvert la connexion Intune du voisin"


# ── Tests ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("appel", appels_generiques(), ids=lambda a: a.nom)
def test_une_route_ne_donne_jamais_acces_aux_donnees_d_un_autre_client(client, session_factory, temoins, appel):
    assert not appel.parametres_inconnus, (
        f"{appel.modele} : paramètre(s) {appel.parametres_inconnus} sans objet du voisin associé — "
        "ajoutez-les à VALEURS_DE_CHEMIN"
    )

    _verifier_isolation(client, session_factory, temoins, appel)


@pytest.mark.parametrize("appel", appels_croises(), ids=lambda a: f"{a.nom} {a.options}")
def test_un_objet_du_client_ne_peut_pas_referencer_un_objet_d_un_autre_client(client, session_factory, temoins, appel):
    _verifier_isolation(client, session_factory, temoins, appel)


def test_un_asset_peut_referencer_les_objets_de_son_propre_client(client):
    references = {"default_profile_id": V.profil_client, "default_credential_id": V.credential_client}

    cree = client.post("/assets", json={"name": "enfant", "parent_id": V.asset_client, **references})
    modifie = client.patch(f"/assets/{V.asset_client}", json=references)

    assert cree.status_code == 200, cree.text
    assert {k: cree.json()[k] for k in ("parent_id", *references)} == {"parent_id": V.asset_client, **references}
    assert modifie.status_code == 200, modifie.text
    assert {k: modifie.json()[k] for k in references} == references


def test_une_planification_peut_utiliser_un_profil_de_son_propre_client(client, db):
    reponse = client.post("/scan/schedules", json={"target": "10.0.0.1", "profile_id": V.profil_client})

    assert reponse.status_code == 200, reponse.text
    assert db.get(models.ScanSchedule, reponse.json()["id"]).profile_id == V.profil_client


def test_le_jeu_de_donnees_du_voisin_contient_bien_la_marque_partout(session_factory, donnees):
    # Garde-fou du test lui-même : chaque table du voisin est peuplée, sinon
    # une fuite sur cette table passerait inaperçue.
    tables_vides = [nom for nom, lignes in photographie(session_factory).items() if not lignes]

    assert tables_vides == []


def test_le_test_couvre_toutes_les_routes_de_l_application():
    from app.main import app

    attendues = {(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods} - {("GET", "/healthz")}
    couvertes = {(m, r.path) for r in routes_de_l_api() for m in r.methods}

    assert attendues == couvertes


def test_chaque_exclusion_designe_une_route_existante():
    existantes = {(m, r.path) for r in routes_de_l_api() for m in r.methods}

    assert set(HORS_PERIMETRE) - existantes == set()
