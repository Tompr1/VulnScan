import httpx
import pytest

from app.inventory.intune.graph_client import GraphAuthError, GraphError, GraphPermissionError
from tests.fakes import FakeClock
from tests.unit.inventory.graph_fakes import TOKEN_PATH, FakeGraph, graph_page, token_response

DEVICES = "/v1.0/deviceManagement/managedDevices"


def test_le_client_s_authentifie_par_client_credentials_puis_appelle_graph_avec_le_jeton():
    # Arrange
    graph = FakeGraph({("GET", DEVICES): graph_page([{"id": "d1"}])})

    # Act
    body = graph.client().get("/deviceManagement/managedDevices", {"$top": 1})

    # Assert
    token_request, graph_request = graph.requests
    form = dict(httpx.QueryParams(token_request.content.decode()))
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == "https://graph.microsoft.com/.default"
    assert graph_request.headers["Authorization"] == "Bearer token-1"
    assert graph_request.url.params["$top"] == "1"
    assert body["value"] == [{"id": "d1"}]


def test_le_jeton_est_reutilise_tant_qu_il_est_valide():
    graph = FakeGraph({("GET", DEVICES): graph_page([])})
    client = graph.client()

    client.get("/deviceManagement/managedDevices")
    client.get("/deviceManagement/managedDevices")

    assert sum(r.url.path == TOKEN_PATH for r in graph.requests) == 1


def test_un_jeton_proche_de_l_expiration_est_renouvele():
    clock = FakeClock()
    graph = FakeGraph({("POST", TOKEN_PATH): [token_response("t1"), token_response("t2")], ("GET", DEVICES): graph_page([])})
    client = graph.client(monotonic=clock.monotonic)

    client.get("/deviceManagement/managedDevices")
    clock.advance(3600 - 60)  # inside the refresh margin
    client.get("/deviceManagement/managedDevices")

    assert [r.headers.get("Authorization") for r in graph.graph_calls()] == ["Bearer t1", "Bearer t2"]


def test_toutes_les_pages_d_une_collection_sont_lues():
    next_link = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=abc"
    graph = FakeGraph({("GET", DEVICES): [graph_page([{"id": "d1"}, {"id": "d2"}], next_link), graph_page([{"id": "d3"}])]})

    items = list(graph.client().get_all("/deviceManagement/managedDevices"))

    assert [i["id"] for i in items] == ["d1", "d2", "d3"]
    assert graph.graph_calls()[1].url.params["$skiptoken"] == "abc"


def test_une_limitation_de_debit_est_reessayee_apres_le_delai_demande():
    throttled = httpx.Response(429, headers={"Retry-After": "7"}, json={"error": {"message": "Too many requests"}})
    graph = FakeGraph({("GET", DEVICES): [throttled, graph_page([{"id": "d1"}])]})

    body = graph.client().get("/deviceManagement/managedDevices")

    assert body["value"] == [{"id": "d1"}]
    assert graph.sleeps == [7.0]


def test_sans_retry_after_les_reessais_s_espacent_exponentiellement():
    graph = FakeGraph({("GET", DEVICES): [httpx.Response(503), httpx.Response(503), graph_page([])]})

    graph.client().get("/deviceManagement/managedDevices")

    assert graph.sleeps == [1.0, 2.0]


def test_une_limitation_persistante_finit_par_une_erreur():
    graph = FakeGraph({("GET", DEVICES): [httpx.Response(429, headers={"Retry-After": "1"})]})

    with pytest.raises(GraphError, match="throttling"):
        graph.client(max_retries=2).get("/deviceManagement/managedDevices")


def test_un_jeton_refuse_par_graph_est_renouvele_une_fois():
    graph = FakeGraph({
        ("POST", TOKEN_PATH): [token_response("old"), token_response("new")],
        ("GET", DEVICES): [httpx.Response(401), graph_page([{"id": "d1"}])],
    })

    assert graph.client().get("/deviceManagement/managedDevices")["value"] == [{"id": "d1"}]


def test_une_permission_manquante_indique_laquelle_accorder():
    forbidden = httpx.Response(403, json={"error": {"code": "Forbidden", "message": "Application is not authorized"}})
    graph = FakeGraph({("GET", DEVICES): forbidden})

    with pytest.raises(GraphPermissionError, match="DeviceManagementManagedDevices.Read.All"):
        graph.client().get("/deviceManagement/managedDevices")


@pytest.mark.parametrize(
    ("aad_error", "hint"),
    [
        ("AADSTS7000215: Invalid client secret provided.", "the client secret is wrong"),
        ("AADSTS7000222: The provided client secret keys are expired.", "the client secret has expired"),
        ("AADSTS700016: Application with identifier 'x' was not found.", "no application with this client ID"),
        ("AADSTS90002: Tenant 'x' not found.", "the tenant ID does not exist"),
    ],
)
def test_un_refus_d_entra_id_est_traduit_en_message_actionnable(aad_error, hint):
    refused = httpx.Response(401, json={"error": "invalid_client", "error_description": aad_error + "\r\nTrace ID: 123"})
    graph = FakeGraph({("POST", TOKEN_PATH): refused})

    with pytest.raises(GraphAuthError, match=hint):
        graph.client().get("/deviceManagement/managedDevices")


def test_le_secret_n_apparait_pas_dans_la_representation_des_identifiants():
    from tests.unit.inventory.graph_fakes import CREDENTIALS

    assert "s3cr3t" not in repr(CREDENTIALS)
