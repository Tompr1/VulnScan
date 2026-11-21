"""
Fake Microsoft Graph / Entra ID endpoints for httpx.MockTransport.

Routes are declared as {(METHOD, path): handler-or-list-of-responses}; a list
is consumed one response per call, so retries can be scripted.
"""
from __future__ import annotations

from collections.abc import Callable

import httpx

from app.inventory.intune.graph_client import EntraAppCredentials, GraphClient

TENANT = "11111111-2222-3333-4444-555555555555"
CREDENTIALS = EntraAppCredentials(TENANT, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "s3cr3t~value")
TOKEN_PATH = f"/{TENANT}/oauth2/v2.0/token"


def token_response(token="token-1", expires_in=3600):
    return httpx.Response(200, json={"token_type": "Bearer", "expires_in": expires_in, "access_token": token})


class FakeGraph:
    def __init__(self, routes: dict[tuple[str, str], Callable | list | httpx.Response] | None = None):
        self.routes = {("POST", TOKEN_PATH): token_response, **(routes or {})}
        self.requests: list[httpx.Request] = []
        self.sleeps: list[float] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get((request.method, request.url.path))
        if route is None:
            return httpx.Response(404, json={"error": {"code": "NotFound", "message": request.url.path}})
        if isinstance(route, list):
            return route.pop(0) if len(route) > 1 else route[0]
        if isinstance(route, httpx.Response):
            return route
        return route(request) if _takes_request(route) else route()

    def client(self, **kwargs) -> GraphClient:
        return GraphClient(CREDENTIALS, http=httpx.Client(transport=httpx.MockTransport(self)),
                           sleep=self.sleeps.append, **kwargs)

    def graph_calls(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == "graph.microsoft.com"]


def _takes_request(handler: Callable) -> bool:
    """True when the handler has a required parameter (the request)."""
    code = handler.__code__
    return code.co_argcount - len(handler.__defaults__ or ()) >= 1


def graph_page(items, next_link=None):
    body = {"value": list(items)}
    if next_link:
        body["@odata.nextLink"] = next_link
    return httpx.Response(200, json=body)
