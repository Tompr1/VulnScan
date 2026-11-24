"""
Access administration of the MSP — global admins only.

Clients, client groups, users, user groups, and the grants tying them: a
role given to a user or a user group, on a client or a client group. Each
user's effective access is explained client by client: which grants reach
it, through which group, and which one sets the role.

An admin of a client still manages the accounts confined to that client
from Settings → Users (app.api.routes_settings).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.access.domain import Grant, Role
from app.access.repository import SqlAccessRepository
from app.api.deps import get_db, require_global_admin, require_user
from app.core.password import PASSWORD_MIN_LENGTH, hash_password
from app.db import models
from app.db.session import Base

logger = logging.getLogger("vulnscan.access")

router = APIRouter(prefix="/access", tags=["access"], dependencies=[Depends(require_global_admin)])

# Rows of these tables describe a client's access or settings, not its data:
# deleting the client deletes them with it.
_CLIENT_ACCESS_TABLES = {"access_grants", "client_group_members", "workspace_settings", "audit_logs"}


class NameBody(BaseModel):
    name: str = Field(min_length=1, max_length=255)


# ─── Clients ──────────────────────────────────────────────────────────────────

@router.get("/clients")
def list_clients(db: Session = Depends(get_db)):
    groups = _memberships(db, models.ClientGroupMember.workspace_id, models.ClientGroupMember.client_group_id)
    grants = dict(
        db.query(models.AccessGrant.workspace_id, func.count())
        .filter(models.AccessGrant.workspace_id.isnot(None))
        .group_by(models.AccessGrant.workspace_id)
    )
    return [
        {"id": c.id, "name": c.name, "group_ids": groups.get(c.id, []), "grant_count": grants.get(c.id, 0)}
        for c in _by_name(db.query(models.Workspace))
    ]


@router.post("/clients", status_code=201)
def create_client(body: NameBody, db: Session = Depends(get_db)):
    name = _unique_name(db, models.Workspace, body.name)
    client = models.Workspace(name=name)
    db.add(client)
    db.commit()
    logger.info("Client created: #%d %s", client.id, name)
    return {"id": client.id, "name": client.name}


@router.patch("/clients/{client_id}")
def rename_client(client_id: int, body: NameBody, db: Session = Depends(get_db)):
    client = _get(db, models.Workspace, client_id, "Client")
    client.name = _unique_name(db, models.Workspace, body.name, exclude_id=client_id)
    db.commit()
    return {"id": client.id, "name": client.name}


@router.delete("/clients/{client_id}")
def delete_client(client_id: int, db: Session = Depends(get_db)):
    """Delete an empty client. A client with data (assets, scans, findings,
    devices…) is kept: its data would be lost for good."""
    client = _get(db, models.Workspace, client_id, "Client")
    if db.query(models.Workspace).count() == 1:
        raise HTTPException(409, "The last client cannot be deleted")
    data = _client_data(db, client_id)
    if data:
        summary = ", ".join(f"{count} {table}" for table, count in data.items())
        raise HTTPException(409, f"Client '{client.name}' still has data ({summary}): it cannot be deleted")
    for model in (models.AccessGrant, models.ClientGroupMember, models.WorkspaceSetting):
        db.query(model).filter(model.workspace_id == client_id).delete(synchronize_session=False)
    db.delete(client)
    db.commit()
    logger.info("Client deleted: #%d %s", client_id, client.name)
    return {"ok": True}


def _client_data(db: Session, client_id: int) -> dict[str, int]:
    """Rows of the client's own data, by table (empty when there is none)."""
    found = {}
    for table in Base.metadata.sorted_tables:
        if table.name in _CLIENT_ACCESS_TABLES or "workspace_id" not in table.c:
            continue
        count = db.query(func.count()).select_from(table).filter(table.c.workspace_id == client_id).scalar()
        if count:
            found[table.name] = count
    return found


# ─── Client groups ────────────────────────────────────────────────────────────

class ClientGroupBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    client_ids: list[int] | None = None


@router.get("/client-groups")
def list_client_groups(db: Session = Depends(get_db)):
    members = _memberships(db, models.ClientGroupMember.client_group_id, models.ClientGroupMember.workspace_id)
    return [{"id": g.id, "name": g.name, "client_ids": members.get(g.id, [])} for g in _by_name(db.query(models.ClientGroup))]


@router.post("/client-groups", status_code=201)
def create_client_group(body: ClientGroupBody, db: Session = Depends(get_db)):
    if body.name is None:
        raise HTTPException(422, "name is required")
    group = models.ClientGroup(name=_unique_name(db, models.ClientGroup, body.name))
    db.add(group)
    db.flush()
    _set_members(db, models.ClientGroupMember, "client_group_id", group.id, "workspace_id",
                 _existing(db, models.Workspace, body.client_ids or [], "Client"))
    db.commit()
    return {"id": group.id, "name": group.name, "client_ids": sorted(set(body.client_ids or []))}


@router.patch("/client-groups/{group_id}")
def update_client_group(group_id: int, body: ClientGroupBody, db: Session = Depends(get_db)):
    group = _get(db, models.ClientGroup, group_id, "Client group")
    if body.name is not None:
        group.name = _unique_name(db, models.ClientGroup, body.name, exclude_id=group_id)
    if body.client_ids is not None:
        _set_members(db, models.ClientGroupMember, "client_group_id", group_id, "workspace_id",
                     _existing(db, models.Workspace, body.client_ids, "Client"))
    db.commit()
    return {"id": group.id, "name": group.name}


@router.delete("/client-groups/{group_id}")
def delete_client_group(group_id: int, db: Session = Depends(get_db)):
    """Its members stay; the grants given on the group go with it."""
    group = _get(db, models.ClientGroup, group_id, "Client group")
    db.query(models.AccessGrant).filter(models.AccessGrant.client_group_id == group_id).delete(synchronize_session=False)
    db.query(models.ClientGroupMember).filter(models.ClientGroupMember.client_group_id == group_id).delete(synchronize_session=False)
    db.delete(group)
    db.commit()
    return {"ok": True}


# ─── Users ────────────────────────────────────────────────────────────────────

class UserCreateBody(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str
    is_global_admin: bool = False


class UserUpdateBody(BaseModel):
    is_global_admin: bool | None = None
    password: str | None = None


@router.get("/users")
def list_users(db: Session = Depends(get_db)):
    groups = _memberships(db, models.UserGroupMember.user_id, models.UserGroupMember.user_group_id)
    access = SqlAccessRepository(db).all_access()
    return [
        {
            "id": u.id,
            "email": u.email,
            "is_global_admin": u.is_global_admin,
            "group_ids": groups.get(u.id, []),
            "client_count": len(access[u.id].roles),
            "created_at": _iso(u.created_at),
            "last_login_at": _iso(u.last_login_at),
        }
        for u in db.query(models.User).order_by(func.lower(models.User.email))
    ]


@router.post("/users", status_code=201)
def create_user(body: UserCreateBody, db: Session = Depends(get_db)):
    email = body.email.strip()
    if "@" not in email:
        raise HTTPException(422, "A valid email is required")
    _check_password(body.password)
    if db.query(models.User).filter(func.lower(models.User.email) == email.lower()).first():
        raise HTTPException(409, f"User '{email}' already exists")
    user = models.User(email=email, password_hash=hash_password(body.password), is_global_admin=body.is_global_admin)
    db.add(user)
    db.commit()
    logger.info("User created: #%d %s (global admin: %s)", user.id, email, body.is_global_admin)
    return {"id": user.id, "email": user.email, "is_global_admin": user.is_global_admin}


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    body: UserUpdateBody,
    me: models.User = Depends(require_user),
    db: Session = Depends(get_db),
):
    user = _get(db, models.User, user_id, "User")
    # The caller is a global admin: refusing to demote or delete oneself is
    # enough for the platform to always keep one.
    if body.is_global_admin is False and user.id == me.id:
        raise HTTPException(409, "You cannot remove your own global admin role")
    if body.is_global_admin is not None:
        user.is_global_admin = body.is_global_admin
    if body.password is not None:
        _check_password(body.password)
        user.password_hash = hash_password(body.password)
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": user.id, "email": user.email, "is_global_admin": user.is_global_admin}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, me: models.User = Depends(require_user), db: Session = Depends(get_db)):
    user = _get(db, models.User, user_id, "User")
    if user.id == me.id:
        raise HTTPException(409, "You cannot delete your own account")
    db.query(models.AccessGrant).filter(models.AccessGrant.user_id == user_id).delete(synchronize_session=False)
    db.query(models.UserGroupMember).filter(models.UserGroupMember.user_id == user_id).delete(synchronize_session=False)
    db.delete(user)
    db.commit()
    logger.info("User deleted: #%d %s", user_id, user.email)
    return {"ok": True}


@router.get("/users/{user_id}/access")
def effective_access(user_id: int, db: Session = Depends(get_db)):
    """What this user may open, and why: for each client, its role and the
    grants reaching it (directly or through a user group, on the client or
    on a client group), the first one setting the role."""
    user = _get(db, models.User, user_id, "User")
    repository = SqlAccessRepository(db)
    access = repository.access_of(user)
    clients = dict(db.query(models.Workspace.id, models.Workspace.name))
    user_groups = dict(db.query(models.UserGroup.id, models.UserGroup.name))
    client_groups = dict(db.query(models.ClientGroup.id, models.ClientGroup.name))
    explained = repository.explain(user)

    def source(grant: Grant, effective: bool) -> dict:
        return {
            "grant_id": grant.grant_id,
            "role": grant.role.value,
            "user_group": _named(grant.user_group_id, user_groups),
            "client_group": _named(grant.client_group_id, client_groups),
            "effective": effective,
        }

    rows = []
    for client_id, role in access.roles.items():
        grants = explained.get(client_id, [])
        rows.append({
            "id": client_id,
            "name": clients[client_id],
            "role": role.value,
            "global_admin": user.is_global_admin,
            "via": [source(grant, not user.is_global_admin and i == 0) for i, grant in enumerate(grants)],
        })
    return {
        "user": {"id": user.id, "email": user.email, "is_global_admin": user.is_global_admin},
        "clients": sorted(rows, key=lambda row: row["name"].lower()),
    }


def _check_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise HTTPException(422, f"The password must be at least {PASSWORD_MIN_LENGTH} characters")


# ─── User groups ──────────────────────────────────────────────────────────────

class UserGroupBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    user_ids: list[int] | None = None


@router.get("/user-groups")
def list_user_groups(db: Session = Depends(get_db)):
    members = _memberships(db, models.UserGroupMember.user_group_id, models.UserGroupMember.user_id)
    return [{"id": g.id, "name": g.name, "user_ids": members.get(g.id, [])} for g in _by_name(db.query(models.UserGroup))]


@router.post("/user-groups", status_code=201)
def create_user_group(body: UserGroupBody, db: Session = Depends(get_db)):
    if body.name is None:
        raise HTTPException(422, "name is required")
    group = models.UserGroup(name=_unique_name(db, models.UserGroup, body.name))
    db.add(group)
    db.flush()
    _set_members(db, models.UserGroupMember, "user_group_id", group.id, "user_id",
                 _existing(db, models.User, body.user_ids or [], "User"))
    db.commit()
    return {"id": group.id, "name": group.name, "user_ids": sorted(set(body.user_ids or []))}


@router.patch("/user-groups/{group_id}")
def update_user_group(group_id: int, body: UserGroupBody, db: Session = Depends(get_db)):
    group = _get(db, models.UserGroup, group_id, "User group")
    if body.name is not None:
        group.name = _unique_name(db, models.UserGroup, body.name, exclude_id=group_id)
    if body.user_ids is not None:
        _set_members(db, models.UserGroupMember, "user_group_id", group_id, "user_id",
                     _existing(db, models.User, body.user_ids, "User"))
    db.commit()
    return {"id": group.id, "name": group.name}


@router.delete("/user-groups/{group_id}")
def delete_user_group(group_id: int, db: Session = Depends(get_db)):
    """Its members stay; the grants given to the group go with it."""
    group = _get(db, models.UserGroup, group_id, "User group")
    db.query(models.AccessGrant).filter(models.AccessGrant.user_group_id == group_id).delete(synchronize_session=False)
    db.query(models.UserGroupMember).filter(models.UserGroupMember.user_group_id == group_id).delete(synchronize_session=False)
    db.delete(group)
    db.commit()
    return {"ok": True}


# ─── Grants ───────────────────────────────────────────────────────────────────

class GrantBody(BaseModel):
    role: Role
    user_id: int | None = None
    user_group_id: int | None = None
    client_id: int | None = None
    client_group_id: int | None = None


class GrantRoleBody(BaseModel):
    role: Role


@router.get("/grants")
def list_grants(db: Session = Depends(get_db)):
    users = dict(db.query(models.User.id, models.User.email))
    user_groups = dict(db.query(models.UserGroup.id, models.UserGroup.name))
    clients = dict(db.query(models.Workspace.id, models.Workspace.name))
    client_groups = dict(db.query(models.ClientGroup.id, models.ClientGroup.name))
    return [
        {
            "id": g.id,
            "role": g.role,
            "user": {"id": g.user_id, "email": users.get(g.user_id)} if g.user_id is not None else None,
            "user_group": _named(g.user_group_id, user_groups),
            "client": _named(g.workspace_id, clients),
            "client_group": _named(g.client_group_id, client_groups),
        }
        for g in db.query(models.AccessGrant).order_by(models.AccessGrant.id)
    ]


@router.post("/grants", status_code=201)
def create_grant(body: GrantBody, db: Session = Depends(get_db)):
    if (body.user_id is None) == (body.user_group_id is None):
        raise HTTPException(422, "Give the role to exactly one of user_id or user_group_id")
    if (body.client_id is None) == (body.client_group_id is None):
        raise HTTPException(422, "Give the role on exactly one of client_id or client_group_id")
    if body.user_id is not None:
        _get(db, models.User, body.user_id, "User")
    else:
        _get(db, models.UserGroup, body.user_group_id, "User group")
    if body.client_id is not None:
        _get(db, models.Workspace, body.client_id, "Client")
    else:
        _get(db, models.ClientGroup, body.client_group_id, "Client group")
    same = db.query(models.AccessGrant).filter(
        _is(models.AccessGrant.user_id, body.user_id),
        _is(models.AccessGrant.user_group_id, body.user_group_id),
        _is(models.AccessGrant.workspace_id, body.client_id),
        _is(models.AccessGrant.client_group_id, body.client_group_id),
    ).first()
    if same is not None:
        raise HTTPException(409, f"This access is already granted (grant #{same.id}): change its role instead")
    grant = models.AccessGrant(
        user_id=body.user_id, user_group_id=body.user_group_id,
        workspace_id=body.client_id, client_group_id=body.client_group_id, role=body.role.value,
    )
    db.add(grant)
    db.commit()
    return {"id": grant.id, "role": grant.role}


@router.patch("/grants/{grant_id}")
def change_grant_role(grant_id: int, body: GrantRoleBody, db: Session = Depends(get_db)):
    grant = _get(db, models.AccessGrant, grant_id, "Grant")
    grant.role = body.role.value
    db.commit()
    return {"id": grant.id, "role": grant.role}


@router.delete("/grants/{grant_id}")
def delete_grant(grant_id: int, db: Session = Depends(get_db)):
    db.delete(_get(db, models.AccessGrant, grant_id, "Grant"))
    db.commit()
    return {"ok": True}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get(db: Session, model, row_id: int, label: str):
    row = db.get(model, row_id)
    if row is None:
        raise HTTPException(404, f"{label} not found")
    return row


def _existing(db: Session, model, ids: list[int], label: str) -> set[int]:
    wanted = set(ids)
    found = {row.id for row in db.query(model.id).filter(model.id.in_(wanted))} if wanted else set()
    missing = sorted(wanted - found)
    if missing:
        raise HTTPException(404, f"{label} not found: {', '.join(map(str, missing))}")
    return wanted


def _set_members(db: Session, member_model, group_column: str, group_id: int, member_column: str, ids: set[int]) -> None:
    """Replace a group's members."""
    db.query(member_model).filter(getattr(member_model, group_column) == group_id).delete(synchronize_session=False)
    db.add_all(member_model(**{group_column: group_id, member_column: member_id}) for member_id in sorted(ids))


def _memberships(db: Session, key_column, value_column) -> dict[int, list[int]]:
    found: dict[int, list[int]] = {}
    for key, value in db.query(key_column, value_column).order_by(value_column):
        found.setdefault(key, []).append(value)
    return found


def _unique_name(db: Session, model, name: str, exclude_id: int | None = None) -> str:
    """The trimmed name, unless another row has it (case aside): 409."""
    name = name.strip()
    if not name:
        raise HTTPException(422, "The name cannot be empty")
    query = db.query(model.id).filter(func.lower(model.name) == name.lower())
    if exclude_id is not None:
        query = query.filter(model.id != exclude_id)
    if query.first() is not None:
        raise HTTPException(409, f"'{name}' already exists")
    return name


def _by_name(query):
    return sorted(query.all(), key=lambda row: row.name.lower())


def _named(row_id: int | None, names: dict[int, str]) -> dict | None:
    return {"id": row_id, "name": names.get(row_id)} if row_id is not None else None


def _is(column, value):
    return column.is_(None) if value is None else column == value


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None
