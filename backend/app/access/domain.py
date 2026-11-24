"""
Access domain — pure rules, no database.

A client is a workspace. A user reaches a client through grants: given to the
user or to one of its user groups, on the client itself or on a client group
holding it. When several grants reach the same client the highest role wins.
A global admin is admin of every client, with or without grants.
"""
from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _RANKS[self]


_RANKS = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}


@dataclass(frozen=True)
class Grant:
    """A role on one client, or on every client of a client group.

    ``grant_id`` and ``user_group_id`` (the group it was given to, None when
    given to the user itself) only say where the grant comes from.
    """

    role: Role
    client_id: int | None = None
    client_group_id: int | None = None
    grant_id: int | None = field(default=None, compare=False)
    user_group_id: int | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if (self.client_id is None) == (self.client_group_id is None):
            raise ValueError("a grant targets exactly one client or one client group")


@dataclass(frozen=True)
class UserAccess:
    """What one user may open: its role on each client it reaches."""

    user_id: int
    is_global_admin: bool = False
    roles: Mapping[int, Role] = field(default_factory=dict)

    @property
    def client_ids(self) -> list[int]:
        return sorted(self.roles)

    def role_on(self, client_id: int) -> Role | None:
        return self.roles.get(client_id)

    def default_client(self) -> int | None:
        """The client opened when none is chosen: the oldest one reachable."""
        return min(self.roles, default=None)

    def is_confined_to(self, client_id: int) -> bool:
        """True when this user reaches this client and nothing else, so an
        admin of that client may manage the account without touching others."""
        return not self.is_global_admin and set(self.roles) == {client_id}


class AccessResolver:
    """Turns a user's grants into its role on each client."""

    def __init__(self, client_ids: Collection[int], client_groups: Mapping[int, Collection[int]]) -> None:
        self._client_ids = frozenset(client_ids)
        self._client_groups = client_groups

    def resolve(self, user_id: int, grants: Iterable[Grant], is_global_admin: bool = False) -> UserAccess:
        if is_global_admin:
            roles = {client_id: Role.ADMIN for client_id in self._client_ids}
            return UserAccess(user_id, True, dict(sorted(roles.items())))
        roles = {client_id: reaching[0].role for client_id, reaching in self.explain(grants).items()}
        return UserAccess(user_id, False, dict(sorted(roles.items())))

    def explain(self, grants: Iterable[Grant]) -> dict[int, list[Grant]]:
        """The grants reaching each client, the one that sets the role first
        (highest role; between equals, the order given)."""
        reaching: dict[int, list[Grant]] = {}
        for grant in grants:
            for client_id in self._clients_of(grant):
                reaching.setdefault(client_id, []).append(grant)
        return {
            client_id: sorted(found, key=lambda grant: -grant.role.rank)
            for client_id, found in sorted(reaching.items())
        }

    def _clients_of(self, grant: Grant) -> set[int]:
        """Existing clients a grant reaches; deleted ones are ignored."""
        if grant.client_id is not None:
            targets = {grant.client_id}
        else:
            targets = set(self._client_groups.get(grant.client_group_id, ()))
        return targets & self._client_ids
