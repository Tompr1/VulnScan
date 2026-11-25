"""
Shared FastAPI dependencies for route handlers.

A session token names a user (``uid``) and, once a client is chosen, that
client (``ws``). The role is never trusted from the token: it is read again
from the access grants on every request, so a grant removed or lowered takes
effect immediately, without waiting for the token to expire.
"""
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.access.domain import Role
from app.access.repository import SqlAccessRepository
from app.core.auth import require_auth
from app.db import models
from app.db.session import SessionLocal, get_db  # noqa: F401 - re-exported

NO_CLIENT_SELECTED = "No client selected: choose one with POST /auth/select-client/{client_id}"


def require_user(claims: dict = Depends(require_auth), db: Session = Depends(get_db)) -> models.User:
    """The account behind the token; 401 when the token names none (old
    token) or the account was deleted since."""
    user = db.get(models.User, claims["uid"]) if claims.get("uid") else None
    if user is None:
        raise HTTPException(status_code=401, detail="Session expired: log in again")
    return user


def require_role(*roles: str):
    """
    Dependency factory — requires a chosen client on which the user currently
    holds one of the given roles. Returns the claims, ``role`` being the one
    held now.

    Usage:
        @router.post("/admin-only")
        def admin_endpoint(claims=Depends(require_role("admin"))):
            ...
    """
    allowed = {Role(r) for r in roles}

    def _check(
        claims: dict = Depends(require_auth),
        user: models.User = Depends(require_user),
        db: Session = Depends(get_db),
    ) -> dict:
        client_id = claims.get("ws")
        if client_id is None:
            raise HTTPException(status_code=403, detail=NO_CLIENT_SELECTED)
        role = SqlAccessRepository(db).access_of(user).role_on(client_id)
        if role is None:
            raise HTTPException(status_code=403, detail="No access to this client")
        if role not in allowed:
            raise HTTPException(status_code=403, detail=f"Requires one of roles: {list(roles)}")
        return {**claims, "role": role.value}

    return _check


def require_shared_reader(*roles: str):
    """
    Dependency factory for what every client shares (reference datasets,
    Threat Intel, platform version): a global admin reads it from any
    session, Root included (no client open); anyone else needs one of the
    given roles on the open client.
    """
    client_check = require_role(*roles)

    def _check(
        claims: dict = Depends(require_auth),
        user: models.User = Depends(require_user),
        db: Session = Depends(get_db),
    ) -> dict:
        if user.is_global_admin:
            return claims
        return client_check(claims=claims, user=user, db=db)

    return _check


def require_global_admin(claims: dict = Depends(require_auth), user: models.User = Depends(require_user)) -> dict:
    """Requires a global admin of the MSP, checked in the database: for what
    every client shares, such as the reference datasets."""
    if not user.is_global_admin:
        raise HTTPException(status_code=403, detail="Requires a global admin")
    return claims
