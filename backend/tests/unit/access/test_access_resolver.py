import pytest

from app.access.domain import AccessResolver, Grant, Role, UserAccess

CLIENTS = [1, 2, 3, 4]
GROUPES = {10: [1, 2], 20: [2, 3]}  # groupes de clients


def resolver(clients=CLIENTS, groupes=GROUPES):
    return AccessResolver(clients, groupes)


def sur_client(client_id, role=Role.VIEWER):
    return Grant(role, client_id=client_id)


def sur_groupe(groupe_id, role=Role.VIEWER):
    return Grant(role, client_group_id=groupe_id)


def test_un_utilisateur_sans_droit_n_ouvre_aucun_client():
    acces = resolver().resolve(7, [])

    assert acces.roles == {} and acces.default_client() is None


def test_un_droit_direct_ouvre_ce_client_seulement_avec_son_role():
    acces = resolver().resolve(7, [sur_client(3, Role.ANALYST)])

    assert acces.roles == {3: Role.ANALYST}


def test_un_droit_sur_un_groupe_de_clients_ouvre_chacun_de_ses_membres():
    acces = resolver().resolve(7, [sur_groupe(10, Role.ANALYST)])

    assert acces.roles == {1: Role.ANALYST, 2: Role.ANALYST}


@pytest.mark.parametrize("ordre", [1, -1], ids=["direct d'abord", "groupe d'abord"])
def test_quand_plusieurs_droits_atteignent_un_client_le_role_le_plus_eleve_l_emporte(ordre):
    droits = [sur_client(2, Role.VIEWER), sur_groupe(20, Role.ADMIN), sur_groupe(10, Role.ANALYST)][::ordre]

    acces = resolver().resolve(7, droits)

    assert acces.roles == {1: Role.ANALYST, 2: Role.ADMIN, 3: Role.ADMIN}


def test_un_role_plus_faible_ne_degrade_jamais_un_role_deja_obtenu():
    acces = resolver().resolve(7, [sur_client(1, Role.ADMIN), sur_client(1, Role.ANALYST), sur_client(1, Role.VIEWER)])

    assert acces.role_on(1) is Role.ADMIN


def test_l_admin_global_est_admin_de_tous_les_clients_meme_sans_aucun_droit():
    acces = resolver().resolve(7, [sur_client(1, Role.VIEWER)], is_global_admin=True)

    assert acces.roles == {1: Role.ADMIN, 2: Role.ADMIN, 3: Role.ADMIN, 4: Role.ADMIN}
    assert acces.is_global_admin


def test_un_droit_vers_un_client_ou_un_groupe_disparu_n_ouvre_rien():
    acces = resolver(clients=[1, 2], groupes={10: [1, 9]}).resolve(
        7, [sur_client(5, Role.ADMIN), sur_groupe(99, Role.ADMIN), sur_groupe(10, Role.VIEWER)]
    )

    assert acces.roles == {1: Role.VIEWER}


@pytest.mark.parametrize("cibles", [{}, {"client_id": 1, "client_group_id": 10}], ids=["aucune", "deux"])
def test_un_droit_vise_exactement_un_client_ou_un_groupe(cibles):
    with pytest.raises(ValueError):
        Grant(Role.VIEWER, **cibles)


def test_le_client_ouvert_par_defaut_est_le_plus_ancien_accessible():
    acces = resolver().resolve(7, [sur_client(3), sur_client(2)])

    assert acces.default_client() == 2 and acces.client_ids == [2, 3]


@pytest.mark.parametrize(
    ("acces", "attendu"),
    [
        (UserAccess(7, roles={2: Role.VIEWER}), True),
        (UserAccess(7, roles={2: Role.ADMIN, 3: Role.VIEWER}), False),
        (UserAccess(7, roles={3: Role.ADMIN}), False),
        (UserAccess(7, is_global_admin=True, roles={2: Role.ADMIN}), False),
    ],
    ids=["ce client seul", "aussi un autre client", "un autre client seul", "admin global"],
)
def test_un_compte_n_est_cantonne_a_un_client_que_s_il_n_ouvre_rien_d_autre(acces, attendu):
    assert acces.is_confined_to(2) is attendu


def test_les_roles_sont_ordonnes_du_lecteur_a_l_admin():
    assert Role.VIEWER.rank < Role.ANALYST.rank < Role.ADMIN.rank
