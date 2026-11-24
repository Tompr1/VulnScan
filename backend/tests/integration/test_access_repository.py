"""
Calcul des accès sur une vraie base SQLite : droits directs, via groupes
d'utilisateurs et via groupes de clients.
"""
import pytest
from sqlalchemy.exc import IntegrityError

from app.access.domain import Role
from app.access.repository import SqlAccessRepository
from app.db import models

pytestmark = pytest.mark.integration


@pytest.fixture
def clients(db):
    db.add_all([models.Workspace(id=i, name=f"client-{i}") for i in (1, 2, 3)])
    db.add_all([models.ClientGroup(id=10, name="Région Ouest"), models.UserGroup(id=20, name="Techs N1")])
    db.flush()
    db.add_all([
        models.ClientGroupMember(client_group_id=10, workspace_id=2),
        models.ClientGroupMember(client_group_id=10, workspace_id=3),
    ])
    db.commit()


def utilisateur(db, email, groupe=None, global_admin=False):
    user = models.User(email=email, password_hash="x", is_global_admin=global_admin)
    db.add(user)
    db.flush()
    if groupe:
        db.add(models.UserGroupMember(user_group_id=groupe, user_id=user.id))
    db.commit()
    return user


def droit(db, role, **cible):
    db.add(models.AccessGrant(role=role, **cible))
    db.commit()


def test_les_droits_directs_et_ceux_du_groupe_d_utilisateurs_se_cumulent(db, clients):
    tech = utilisateur(db, "tech@msp.example", groupe=20)
    droit(db, "viewer", user_id=tech.id, workspace_id=1)
    droit(db, "analyst", user_group_id=20, client_group_id=10)

    acces = SqlAccessRepository(db).access_of(tech)

    assert acces.roles == {1: Role.VIEWER, 2: Role.ANALYST, 3: Role.ANALYST}


def test_le_droit_d_un_groupe_ne_profite_pas_a_ceux_qui_n_en_sont_pas_membres(db, clients):
    membre = utilisateur(db, "membre@msp.example", groupe=20)
    autre = utilisateur(db, "autre@msp.example")
    droit(db, "admin", user_group_id=20, workspace_id=1)

    repository = SqlAccessRepository(db)

    assert repository.access_of(membre).roles == {1: Role.ADMIN}
    assert repository.access_of(autre).roles == {}


def test_un_client_atteint_directement_et_par_groupe_garde_le_role_le_plus_eleve(db, clients):
    tech = utilisateur(db, "tech@msp.example", groupe=20)
    droit(db, "admin", user_id=tech.id, workspace_id=2)
    droit(db, "viewer", user_group_id=20, client_group_id=10)

    acces = SqlAccessRepository(db).access_of(tech)

    assert acces.roles == {2: Role.ADMIN, 3: Role.VIEWER}


def test_l_admin_global_ouvre_tous_les_clients(db, clients):
    admin = utilisateur(db, "admin@msp.example", global_admin=True)

    assert SqlAccessRepository(db).access_of(admin).roles == {1: Role.ADMIN, 2: Role.ADMIN, 3: Role.ADMIN}


def test_les_utilisateurs_d_un_client_sont_ceux_qui_l_atteignent_par_un_chemin_quelconque(db, clients):
    admin = utilisateur(db, "admin@msp.example", global_admin=True)
    direct = utilisateur(db, "direct@client2.example")
    par_groupe = utilisateur(db, "groupe@msp.example", groupe=20)
    ailleurs = utilisateur(db, "ailleurs@client1.example")
    droit(db, "viewer", user_id=direct.id, workspace_id=2)
    droit(db, "analyst", user_group_id=20, client_group_id=10)
    droit(db, "admin", user_id=ailleurs.id, workspace_id=1)

    trouves = SqlAccessRepository(db).users_with_access_to(2)

    assert [(u.email, a.role_on(2)) for u, a in trouves] == [
        ("admin@msp.example", Role.ADMIN),
        ("direct@client2.example", Role.VIEWER),
        ("groupe@msp.example", Role.ANALYST),
    ]
    assert admin.id in {u.id for u, _ in trouves} and par_groupe.id in {u.id for u, _ in trouves}


def test_donner_un_client_a_un_utilisateur_cree_un_droit_direct(db, clients):
    tech = utilisateur(db, "tech@msp.example")
    repository = SqlAccessRepository(db)

    repository.grant_client(tech.id, 3, Role.ANALYST)
    db.commit()

    assert repository.access_of(tech).roles == {3: Role.ANALYST}


def test_l_email_d_un_compte_est_unique_sur_tout_le_msp(db, clients):
    utilisateur(db, "tech@msp.example")

    with pytest.raises(IntegrityError):
        utilisateur(db, "tech@msp.example")


@pytest.mark.parametrize(
    "cible",
    [
        {"user_id": 1},
        {"workspace_id": 1},
        {"user_id": 1, "user_group_id": 20, "workspace_id": 1},
        {"user_id": 1, "workspace_id": 1, "client_group_id": 10},
    ],
    ids=["sans client", "sans titulaire", "deux titulaires", "deux clients"],
)
def test_un_droit_a_exactement_un_titulaire_et_une_cible(db, clients, cible):
    utilisateur(db, "tech@msp.example")

    with pytest.raises(IntegrityError):
        droit(db, "viewer", **cible)


def test_un_droit_n_accepte_que_les_roles_connus(db, clients):
    tech = utilisateur(db, "tech@msp.example")

    with pytest.raises(IntegrityError):
        droit(db, "superadmin", user_id=tech.id, workspace_id=1)
