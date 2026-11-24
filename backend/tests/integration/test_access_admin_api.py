"""
Administration des accès du MSP par un admin global : clients, groupes de
clients, comptes, groupes d'utilisateurs, attributions, et l'explication des
droits effectifs d'un compte.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.access.domain import Role
from app.access.repository import SqlAccessRepository
from app.api import routes_access
from app.api.deps import get_db
from app.api.validation import install_validation_error_handler
from app.core.auth import require_auth
from app.core.password import verify_password
from app.db import models
from tests.integration.conftest import POSTGRES_URL

pytestmark = pytest.mark.integration

ACME, GLOBEX, HOPITAL = 1, 2, 3
SANTE = 10  # groupe de clients : l'hôpital
ADMIN_GLOBAL, TECH, LEA = 1, 2, 3
N1 = 20  # groupe d'utilisateurs : le technicien
MOT_DE_PASSE = "Correct-Horse-42"


@pytest.fixture
def msp(db):
    db.add_all([models.Workspace(id=ACME, name="Acme"), models.Workspace(id=GLOBEX, name="Globex"),
                models.Workspace(id=HOPITAL, name="Hôpital")])
    db.add_all([
        models.User(id=ADMIN_GLOBAL, email="admin@msp.example", password_hash="x", is_global_admin=True),
        models.User(id=TECH, email="tech@msp.example", password_hash="x"),
        models.User(id=LEA, email="lea@acme.example", password_hash="x"),
        models.ClientGroup(id=SANTE, name="Santé"),
        models.UserGroup(id=N1, name="Niveau 1"),
    ])
    db.flush()
    db.add_all([
        models.ClientGroupMember(client_group_id=SANTE, workspace_id=HOPITAL),
        models.UserGroupMember(user_group_id=N1, user_id=TECH),
        models.AccessGrant(id=1, user_id=TECH, workspace_id=ACME, role="viewer"),
        models.AccessGrant(id=2, user_group_id=N1, workspace_id=ACME, role="analyst"),
        models.AccessGrant(id=3, user_group_id=N1, client_group_id=SANTE, role="admin"),
        models.AccessGrant(id=4, user_id=LEA, workspace_id=ACME, role="admin"),
    ])
    db.commit()


@pytest.fixture
def client(session_factory, msp):
    app = FastAPI()
    install_validation_error_handler(app)
    app.include_router(routes_access.router)

    def test_db():
        with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = test_db
    connecte(app, ADMIN_GLOBAL)
    return TestClient(app)


def connecte(app, uid, ws=ACME):
    app.dependency_overrides[require_auth] = lambda: {"uid": uid, "ws": ws, "sub": f"user{uid}@msp.example"}


def acces(db, user_id):
    db.expire_all()
    return SqlAccessRepository(db).access_of(db.get(models.User, user_id)).roles


# ── Réservé à l'admin global ─────────────────────────────────────────────────

@pytest.mark.parametrize(("methode", "chemin", "corps"), [
    ("GET", "/access/users", None),
    ("GET", "/access/users/2/access", None),
    ("POST", "/access/clients", {"name": "Pirate"}),
    ("POST", "/access/grants", {"role": "admin", "user_id": 3, "client_id": 2}),
    ("PATCH", "/access/users/3", {"is_global_admin": True}),
])
def test_l_admin_d_un_client_n_administre_pas_les_acces(client, db, methode, chemin, corps):
    connecte(client.app, LEA)  # admin d'Acme

    reponse = client.request(methode, chemin, json=corps)

    assert reponse.status_code == 403
    assert acces(db, LEA) == {ACME: Role.ADMIN}
    assert db.query(models.Workspace).count() == 3


# ── Clients ──────────────────────────────────────────────────────────────────

def test_les_clients_sont_listes_par_nom_avec_leurs_groupes(client):
    reponse = client.get("/access/clients")

    assert reponse.json() == [
        {"id": ACME, "name": "Acme", "group_ids": [], "grant_count": 3},
        {"id": GLOBEX, "name": "Globex", "group_ids": [], "grant_count": 0},
        {"id": HOPITAL, "name": "Hôpital", "group_ids": [SANTE], "grant_count": 0},
    ]


def test_un_nouveau_client_est_ouvert_par_l_admin_global_et_par_personne_d_autre(client, db):
    reponse = client.post("/access/clients", json={"name": "  Initech  "})

    assert reponse.status_code == 201
    nouveau = reponse.json()["id"]
    assert reponse.json()["name"] == "Initech"
    assert acces(db, ADMIN_GLOBAL)[nouveau] is Role.ADMIN
    assert nouveau not in acces(db, TECH)


@pytest.mark.parametrize("nom", ["acme", "ACME ", "Globex"])
def test_deux_clients_ne_portent_pas_le_meme_nom(client, db, nom):
    assert client.post("/access/clients", json={"name": nom}).status_code == 409
    assert client.patch(f"/access/clients/{HOPITAL}", json={"name": nom}).status_code == 409
    assert db.query(models.Workspace).count() == 3


def test_un_client_se_renomme(client, db):
    assert client.patch(f"/access/clients/{GLOBEX}", json={"name": "Globex Corp"}).status_code == 200
    db.expire_all()
    assert db.get(models.Workspace, GLOBEX).name == "Globex Corp"


def test_un_client_vide_se_supprime_avec_ses_acces_et_ses_reglages(client, db):
    db.add_all([
        models.AccessGrant(user_id=LEA, workspace_id=GLOBEX, role="viewer"),
        models.ClientGroupMember(client_group_id=SANTE, workspace_id=GLOBEX),
        models.WorkspaceSetting(workspace_id=GLOBEX, key="scan_allowlist", value_json='{"entries": []}'),
    ])
    db.commit()

    reponse = client.delete(f"/access/clients/{GLOBEX}")

    assert reponse.status_code == 200
    db.expire_all()
    assert db.get(models.Workspace, GLOBEX) is None
    assert db.query(models.AccessGrant).filter_by(workspace_id=GLOBEX).count() == 0
    assert db.query(models.ClientGroupMember).filter_by(workspace_id=GLOBEX).count() == 0
    assert db.query(models.WorkspaceSetting).filter_by(workspace_id=GLOBEX).count() == 0
    assert acces(db, LEA) == {ACME: Role.ADMIN}


def test_un_client_qui_a_des_donnees_n_est_pas_supprime(client, db):
    db.add_all([models.Asset(workspace_id=GLOBEX, name="srv-1"), models.Asset(workspace_id=GLOBEX, name="srv-2")])
    db.add(models.ScanJob(workspace_id=GLOBEX, target="10.0.0.1", status="done"))
    db.commit()

    reponse = client.delete(f"/access/clients/{GLOBEX}")

    assert reponse.status_code == 409
    assert "2 assets" in reponse.json()["detail"] and "1 scan_jobs" in reponse.json()["detail"]
    db.expire_all()
    assert db.get(models.Workspace, GLOBEX) is not None


def test_le_dernier_client_n_est_pas_supprime(client, db):
    for client_id in (GLOBEX, HOPITAL):
        assert client.delete(f"/access/clients/{client_id}").status_code == 200

    assert client.delete(f"/access/clients/{ACME}").status_code == 409
    db.expire_all()
    assert db.get(models.Workspace, ACME) is not None


# ── Groupes de clients ───────────────────────────────────────────────────────

def test_un_droit_sur_un_groupe_de_clients_suit_ses_membres(client, db):
    assert acces(db, TECH) == {ACME: Role.ANALYST, HOPITAL: Role.ADMIN}

    reponse = client.patch(f"/access/client-groups/{SANTE}", json={"client_ids": [HOPITAL, GLOBEX]})

    assert reponse.status_code == 200
    assert acces(db, TECH) == {ACME: Role.ANALYST, GLOBEX: Role.ADMIN, HOPITAL: Role.ADMIN}
    assert client.get("/access/client-groups").json() == [{"id": SANTE, "name": "Santé", "client_ids": [GLOBEX, HOPITAL]}]


def test_un_groupe_de_clients_avec_un_client_inconnu_n_est_pas_cree(client, db):
    reponse = client.post("/access/client-groups", json={"name": "Industrie", "client_ids": [GLOBEX, 99]})

    assert reponse.status_code == 404
    assert db.query(models.ClientGroup).count() == 1


def test_supprimer_un_groupe_de_clients_retire_les_droits_donnes_sur_lui_et_garde_les_clients(client, db):
    assert client.delete(f"/access/client-groups/{SANTE}").status_code == 200

    assert acces(db, TECH) == {ACME: Role.ANALYST}
    assert db.get(models.Workspace, HOPITAL) is not None
    assert db.query(models.AccessGrant).filter_by(id=3).count() == 0


# ── Comptes ──────────────────────────────────────────────────────────────────

def test_les_comptes_sont_listes_avec_leurs_groupes_et_le_nombre_de_clients_ouverts(client):
    comptes = {u["email"]: (u["is_global_admin"], u["group_ids"], u["client_count"]) for u in client.get("/access/users").json()}

    assert comptes == {
        "admin@msp.example": (True, [], 3),
        "lea@acme.example": (False, [], 1),
        "tech@msp.example": (False, [N1], 2),
    }


def test_un_nouveau_compte_n_ouvre_aucun_client_tant_qu_on_ne_lui_attribue_rien(client, db):
    reponse = client.post("/access/users", json={"email": "nouveau@msp.example", "password": MOT_DE_PASSE})

    assert reponse.status_code == 201
    cree = db.query(models.User).filter_by(email="nouveau@msp.example").one()
    assert verify_password(MOT_DE_PASSE, cree.password_hash)
    assert acces(db, cree.id) == {}


@pytest.mark.parametrize(("corps", "statut"), [
    ({"email": "TECH@msp.example", "password": MOT_DE_PASSE}, 409),
    ({"email": "court@msp.example", "password": "12345"}, 422),
    ({"email": "pas-un-email", "password": MOT_DE_PASSE}, 422),
], ids=["email déjà pris", "mot de passe trop court", "email invalide"])
def test_un_compte_invalide_n_est_pas_cree(client, db, corps, statut):
    assert client.post("/access/users", json=corps).status_code == statut
    assert db.query(models.User).count() == 3


def test_un_compte_promu_admin_global_ouvre_tous_les_clients(client, db):
    assert client.patch(f"/access/users/{LEA}", json={"is_global_admin": True}).status_code == 200

    assert acces(db, LEA) == {ACME: Role.ADMIN, GLOBEX: Role.ADMIN, HOPITAL: Role.ADMIN}


def test_l_admin_global_reinitialise_un_mot_de_passe(client, db):
    assert client.patch(f"/access/users/{TECH}", json={"password": "Nouveau-Secret-1"}).status_code == 200
    db.expire_all()
    assert verify_password("Nouveau-Secret-1", db.get(models.User, TECH).password_hash)


def test_un_mot_de_passe_trop_court_n_est_pas_enregistre(client, db):
    assert client.patch(f"/access/users/{TECH}", json={"password": "12345"}).status_code == 422
    db.expire_all()
    assert db.get(models.User, TECH).password_hash == "x"


def test_on_ne_se_retire_pas_son_propre_role_d_admin_global_ni_son_compte(client, db):
    assert client.patch(f"/access/users/{ADMIN_GLOBAL}", json={"is_global_admin": False}).status_code == 409
    assert client.delete(f"/access/users/{ADMIN_GLOBAL}").status_code == 409
    db.expire_all()
    assert db.get(models.User, ADMIN_GLOBAL).is_global_admin


def test_un_autre_admin_global_peut_etre_retrogade(client, db):
    db.get(models.User, LEA).is_global_admin = True
    db.commit()

    assert client.patch(f"/access/users/{LEA}", json={"is_global_admin": False}).status_code == 200
    assert acces(db, LEA) == {ACME: Role.ADMIN}


def test_supprimer_un_compte_supprime_ses_droits_et_ses_appartenances(client, db):
    assert client.delete(f"/access/users/{TECH}").status_code == 200

    db.expire_all()
    assert db.get(models.User, TECH) is None
    assert db.query(models.AccessGrant).filter_by(user_id=TECH).count() == 0
    assert db.query(models.UserGroupMember).filter_by(user_id=TECH).count() == 0


# ── Groupes d'utilisateurs ───────────────────────────────────────────────────

def test_rejoindre_un_groupe_d_utilisateurs_donne_ses_droits(client, db):
    reponse = client.patch(f"/access/user-groups/{N1}", json={"user_ids": [TECH, LEA]})

    assert reponse.status_code == 200
    assert acces(db, LEA) == {ACME: Role.ADMIN, HOPITAL: Role.ADMIN}


def test_quitter_un_groupe_d_utilisateurs_retire_ses_droits(client, db):
    client.patch(f"/access/user-groups/{N1}", json={"user_ids": []})

    assert acces(db, TECH) == {ACME: Role.VIEWER}


def test_un_groupe_d_utilisateurs_se_cree_avec_ses_membres(client, db):
    reponse = client.post("/access/user-groups", json={"name": "Astreinte", "user_ids": [LEA]})

    assert reponse.status_code == 201
    assert client.get("/access/user-groups").json() == [
        {"id": reponse.json()["id"], "name": "Astreinte", "user_ids": [LEA]},
        {"id": N1, "name": "Niveau 1", "user_ids": [TECH]},
    ]


def test_supprimer_un_groupe_d_utilisateurs_retire_les_droits_donnes_au_groupe(client, db):
    assert client.delete(f"/access/user-groups/{N1}").status_code == 200

    assert acces(db, TECH) == {ACME: Role.VIEWER}
    assert db.get(models.User, TECH) is not None
    assert db.query(models.AccessGrant).filter_by(user_group_id=N1).count() == 0


# ── Attributions ─────────────────────────────────────────────────────────────

def test_une_attribution_ouvre_le_client_avec_son_role(client, db):
    reponse = client.post("/access/grants", json={"role": "analyst", "user_id": LEA, "client_id": GLOBEX})

    assert reponse.status_code == 201
    assert acces(db, LEA) == {ACME: Role.ADMIN, GLOBEX: Role.ANALYST}


def test_une_attribution_a_un_groupe_sur_un_groupe_de_clients(client, db):
    groupe = client.post("/access/client-groups", json={"name": "Industrie", "client_ids": [GLOBEX]}).json()["id"]

    client.post("/access/grants", json={"role": "viewer", "user_group_id": N1, "client_group_id": groupe})

    assert acces(db, TECH) == {ACME: Role.ANALYST, GLOBEX: Role.VIEWER, HOPITAL: Role.ADMIN}


@pytest.mark.parametrize(("corps", "statut"), [
    ({"role": "admin", "client_id": GLOBEX}, 422),
    ({"role": "admin", "user_id": LEA, "user_group_id": N1, "client_id": GLOBEX}, 422),
    ({"role": "admin", "user_id": LEA}, 422),
    ({"role": "admin", "user_id": LEA, "client_id": GLOBEX, "client_group_id": SANTE}, 422),
    ({"role": "owner", "user_id": LEA, "client_id": GLOBEX}, 422),
    ({"role": "admin", "user_id": 99, "client_id": GLOBEX}, 404),
    ({"role": "admin", "user_id": LEA, "client_id": 99}, 404),
    ({"role": "admin", "user_group_id": 99, "client_id": GLOBEX}, 404),
    ({"role": "admin", "user_id": LEA, "client_group_id": 99}, 404),
    ({"role": "viewer", "user_id": LEA, "client_id": ACME}, 409),
], ids=["sans bénéficiaire", "deux bénéficiaires", "sans cible", "deux cibles", "rôle inconnu",
        "compte inconnu", "client inconnu", "groupe d'utilisateurs inconnu", "groupe de clients inconnu", "déjà attribué"])
def test_une_attribution_invalide_n_est_pas_creee(client, db, corps, statut):
    assert client.post("/access/grants", json=corps).status_code == statut
    assert db.query(models.AccessGrant).count() == 4


def test_le_role_d_une_attribution_se_change(client, db):
    assert client.patch("/access/grants/4", json={"role": "viewer"}).status_code == 200

    assert acces(db, LEA) == {ACME: Role.VIEWER}


def test_retirer_une_attribution_ferme_le_client(client, db):
    assert client.delete("/access/grants/4").status_code == 200

    assert acces(db, LEA) == {}


def test_les_attributions_nomment_leur_beneficiaire_et_leur_cible(client):
    attributions = client.get("/access/grants").json()

    assert attributions[2] == {
        "id": 3, "role": "admin", "user": None, "user_group": {"id": N1, "name": "Niveau 1"},
        "client": None, "client_group": {"id": SANTE, "name": "Santé"},
    }
    assert attributions[0]["user"] == {"id": TECH, "email": "tech@msp.example"}


# ── Droits effectifs ─────────────────────────────────────────────────────────

def test_les_droits_effectifs_expliquent_pourquoi_le_compte_ouvre_chaque_client(client):
    reponse = client.get(f"/access/users/{TECH}/access")

    assert reponse.status_code == 200
    assert reponse.json() == {
        "user": {"id": TECH, "email": "tech@msp.example", "is_global_admin": False},
        "clients": [
            {
                "id": ACME, "name": "Acme", "role": "analyst", "global_admin": False,
                "via": [
                    {"grant_id": 2, "role": "analyst", "user_group": {"id": N1, "name": "Niveau 1"},
                     "client_group": None, "effective": True},
                    {"grant_id": 1, "role": "viewer", "user_group": None, "client_group": None, "effective": False},
                ],
            },
            {
                "id": HOPITAL, "name": "Hôpital", "role": "admin", "global_admin": False,
                "via": [
                    {"grant_id": 3, "role": "admin", "user_group": {"id": N1, "name": "Niveau 1"},
                     "client_group": {"id": SANTE, "name": "Santé"}, "effective": True},
                ],
            },
        ],
    }


def test_un_admin_global_ouvre_tout_par_son_role_et_pas_par_ses_attributions(client, db):
    db.add(models.AccessGrant(user_id=ADMIN_GLOBAL, workspace_id=GLOBEX, role="viewer"))
    db.commit()

    clients = client.get(f"/access/users/{ADMIN_GLOBAL}/access").json()["clients"]

    assert [(c["name"], c["role"], c["global_admin"]) for c in clients] == [
        ("Acme", "admin", True), ("Globex", "admin", True), ("Hôpital", "admin", True),
    ]
    assert [v["effective"] for v in clients[1]["via"]] == [False]


def test_entre_deux_droits_de_meme_role_le_plus_ancien_est_celui_qui_compte(client, db):
    db.add(models.UserGroup(id=30, name="Astreinte"))
    db.flush()
    db.add_all([models.UserGroupMember(user_group_id=30, user_id=LEA),
                models.AccessGrant(id=7, user_group_id=30, workspace_id=ACME, role="admin")])
    db.commit()

    [acme] = client.get(f"/access/users/{LEA}/access").json()["clients"]

    assert [(v["grant_id"], v["effective"]) for v in acme["via"]] == [(4, True), (7, False)]


def test_les_droits_effectifs_d_un_compte_inconnu(client):
    assert client.get("/access/users/99/access").status_code == 404


# ── Premier client ───────────────────────────────────────────────────────────

def test_une_plateforme_neuve_recoit_un_premier_client_et_un_client_renomme_n_est_pas_recree(session_factory):
    from app.main import _ensure_first_client

    with session_factory() as db:
        _ensure_first_client(db)
        premier = db.query(models.Workspace).one()
        premier.name = "Acme"
        db.commit()
        _ensure_first_client(db)

        assert [w.name for w in db.query(models.Workspace)] == ["Acme"]


def test_supprimer_un_compte_garde_les_scans_qu_il_a_lances(client, db):
    db.add(models.ScanJob(id=40, workspace_id=ACME, target="10.0.0.1", status="done", created_by_user_id=TECH))
    db.commit()

    reponse = client.delete(f"/access/users/{TECH}")

    assert reponse.status_code == 200
    db.expire_all()
    assert db.get(models.ScanJob, 40) is not None
    if POSTGRES_URL:  # SQLite n'applique pas ON DELETE sans PRAGMA foreign_keys
        assert db.get(models.ScanJob, 40).created_by_user_id is None
