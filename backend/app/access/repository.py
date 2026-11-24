"""
SQL side of access control: reads users' grants and groups, and lets the
pure AccessResolver decide (app.access.domain).
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.access.domain import AccessResolver, Grant, Role, UserAccess
from app.db import models


class SqlAccessRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def access_of(self, user: models.User) -> UserAccess:
        grants = self._grants_of([user.id])
        return self._resolver().resolve(user.id, grants[user.id], user.is_global_admin)

    def explain(self, user: models.User) -> dict[int, list[Grant]]:
        """The grants reaching each client this user reaches through grants,
        the one that sets the role first (see AccessResolver.explain)."""
        return self._resolver().explain(self._grants_of([user.id])[user.id])

    def all_access(self) -> dict[int, UserAccess]:
        """Every user's access, by user id."""
        users = self._db.query(models.User).all()
        grants = self._grants_of([user.id for user in users])
        resolver = self._resolver()
        return {user.id: resolver.resolve(user.id, grants[user.id], user.is_global_admin) for user in users}

    def users_with_access_to(self, client_id: int) -> list[tuple[models.User, UserAccess]]:
        """Every user reaching this client, global admins included, by email."""
        users = self._db.query(models.User).order_by(models.User.email).all()
        grants = self._grants_of([user.id for user in users])
        resolver = self._resolver()
        reached = [(user, resolver.resolve(user.id, grants[user.id], user.is_global_admin)) for user in users]
        return [(user, access) for user, access in reached if access.role_on(client_id) is not None]

    def grant_client(self, user_id: int, client_id: int, role: Role) -> None:
        self._db.add(models.AccessGrant(user_id=user_id, workspace_id=client_id, role=role.value))

    def _resolver(self) -> AccessResolver:
        client_ids = [row.id for row in self._db.query(models.Workspace.id)]
        groups: dict[int, set[int]] = defaultdict(set)
        for member in self._db.query(models.ClientGroupMember):
            groups[member.client_group_id].add(member.workspace_id)
        return AccessResolver(client_ids, groups)

    def _grants_of(self, user_ids: Collection[int]) -> dict[int, list[Grant]]:
        """Grants of each user: its own, and those of its user groups."""
        members_of: dict[int, list[int]] = defaultdict(list)
        for member in self._db.query(models.UserGroupMember).filter(models.UserGroupMember.user_id.in_(user_ids)):
            members_of[member.user_group_id].append(member.user_id)

        grants: dict[int, list[Grant]] = defaultdict(list)
        rows = self._db.query(models.AccessGrant).filter(
            or_(models.AccessGrant.user_id.in_(user_ids), models.AccessGrant.user_group_id.in_(list(members_of)))
        )
        for row in rows:
            grant = Grant(
                Role(row.role), client_id=row.workspace_id, client_group_id=row.client_group_id,
                grant_id=row.id, user_group_id=row.user_group_id,
            )
            holders = [row.user_id] if row.user_id is not None else members_of[row.user_group_id]
            for user_id in holders:
                grants[user_id].append(grant)
        for found in grants.values():
            found.sort(key=lambda grant: grant.grant_id or 0)  # oldest first: a stable explanation
        return grants
