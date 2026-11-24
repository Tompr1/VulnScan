"""
Sessions of the MSP interface.

Login checks the password and opens the user's first client (or no client
for a global admin who has none yet); the user then switches client with
POST /auth/select-client/{id}. Every token names the user (``uid``) and the
chosen client (``ws``); the role it carries is informative only, since every
request reads it again from the access grants (app.api.deps.require_role).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.access.domain import UserAccess
from app.access.overview import SqlClientOverview
from app.access.repository import SqlAccessRepository
from app.api.deps import require_user
from app.core.auth import create_token, require_auth
from app.core.geoip import resolve as geoip_resolve
from app.core.net import client_ip
from app.core.password import verify_password, needs_rehash, hash_password
from app.core.rate_limit import rate_limit
from app.db.session import get_db
from app.db import models

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl=Depends(rate_limit(max_requests=5, window_seconds=60)),
):
    user = (
        db.query(models.User)
        .filter(models.User.email == body.email)
        .first()
    )
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access = SqlAccessRepository(db).access_of(user)
    if not access.roles and not user.is_global_admin:
        raise HTTPException(status_code=403, detail="No client is accessible with this account")
    # Auto-migrate legacy SHA256 hashes to bcrypt on successful login
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.last_login_at = datetime.now(timezone.utc)
    ip = client_ip(request)
    user.last_login_ip = ip
    user.last_login_location = geoip_resolve(ip)
    db.commit()
    return _session(db, user, access, access.default_client())


@router.get("/clients")
def my_clients(user: models.User = Depends(require_user), db: Session = Depends(get_db)):
    """The clients the user may open, with what the picker shows of each."""
    access = SqlAccessRepository(db).access_of(user)
    return SqlClientOverview(db).clients_of(access)


@router.post("/select-client/{client_id}")
def select_client(client_id: int, user: models.User = Depends(require_user), db: Session = Depends(get_db)):
    """A new session token opening this client, with the role held there."""
    access = SqlAccessRepository(db).access_of(user)
    if access.role_on(client_id) is None:
        raise HTTPException(status_code=404, detail="Client not found")
    return _session(db, user, access, client_id)


@router.get("/me")
def me(claims=Depends(require_auth)):
    return claims


def _session(db: Session, user: models.User, access: UserAccess, client_id: int | None) -> dict:
    claims = {"sub": user.email, "uid": user.id}
    role = None
    if client_id is not None:
        role = access.role_on(client_id).value
        claims.update(ws=client_id, role=role)
    clients = dict(db.query(models.Workspace.id, models.Workspace.name).filter(models.Workspace.id.in_(access.client_ids)))
    return {
        "token": create_token(claims),
        "workspace_id": client_id,
        "role": role,
        "is_global_admin": user.is_global_admin,
        "clients": [
            {"id": cid, "name": clients[cid], "role": access.role_on(cid).value}
            for cid in access.client_ids
            if cid in clients
        ],
    }
