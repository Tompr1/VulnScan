"""
Shared FastAPI dependencies for route handlers.
"""
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_auth
from app.db import models
from app.db.session import SessionLocal, get_db  # noqa: F401 - re-exported


def require_role(*roles: str):
    """
    Dependency factory — requires the authenticated user to have one of the given roles.

    Usage:
        @router.post("/admin-only")
        def admin_endpoint(claims=Depends(require_role("admin"))):
            ...
    """
    def _check(claims: dict = Depends(require_auth)) -> dict:
        claim_role = str(claims.get("role", "")).lower()
        allowed = {str(r).lower() for r in roles}
        if claim_role not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of roles: {list(roles)}",
            )
        return claims
    return _check


def require_global_admin(claims: dict = Depends(require_auth), db: Session = Depends(get_db)) -> dict:
    """Requires a global admin of the MSP, checked in the database (the token
    only names the user): for what every client shares, such as the
    reference datasets."""
    user = db.get(models.User, claims["uid"]) if claims.get("uid") else None
    if user is None or not user.is_global_admin:
        raise HTTPException(status_code=403, detail="Requires a global admin")
    return claims
