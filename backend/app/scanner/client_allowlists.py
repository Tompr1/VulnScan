"""
The allowlist of each client, read when its scan starts: a change made in
the settings applies to the next scan, in every worker, without a restart.
"""
from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from app.core.workspace_settings import client_allowlist
from app.scanner.allowlist import AllowlistPolicy


SessionFactory = Callable[[], Session]


def client_policy(db: Session, workspace_id: int, platform_default: str | None) -> AllowlistPolicy:
    """The client's allowlist, read in an open session."""
    entries = client_allowlist(db, workspace_id)
    if entries is None:
        return AllowlistPolicy.from_setting(platform_default)
    return AllowlistPolicy.from_setting(",".join(entries))


class SqlClientAllowlists:
    """A client without an allowlist of its own gets the platform default
    (the ``ALLOWLIST`` environment variable)."""

    def __init__(self, session_factory: SessionFactory, platform_default: str | None) -> None:
        self._session_factory = session_factory
        self._platform_default = platform_default

    def policy_for(self, workspace_id: int) -> AllowlistPolicy:
        with self._session_factory() as db:
            return client_policy(db, workspace_id, self._platform_default)
