"""
Inventory collection use case: connection -> source -> snapshot -> storage.

The secret is decrypted here, just before use, and never leaves this module.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.crypto import decrypt_str
from app.db import models
from app.inventory.intune.graph_client import EntraAppCredentials, GraphClient
from app.inventory.intune.source import IntuneSource
from app.inventory.repository import SqlInventoryRepository
from app.inventory.source import InventorySource
from app.inventory.sync import InventorySync, InventorySyncResult

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]
SourceFactory = Callable[[EntraAppCredentials], InventorySource]

_MAX_STATUS_MESSAGE = 1000


class ConnectionNotFoundError(LookupError):
    pass


def intune_source(credentials: EntraAppCredentials) -> InventorySource:
    return IntuneSource(GraphClient(credentials))


def credentials_of(connection: models.InventoryConnection, decrypt: Callable[[str], str] = decrypt_str) -> EntraAppCredentials:
    return EntraAppCredentials(connection.tenant_id, connection.client_id, decrypt(connection.client_secret_enc))


class InventoryCollector:
    def __init__(
        self,
        session_factory: SessionFactory,
        source_factory: SourceFactory = intune_source,
        decrypt: Callable[[str], str] = decrypt_str,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._session_factory = session_factory
        self._source_factory = source_factory
        self._decrypt = decrypt
        self._clock = clock

    def collect(self, connection_id: int, workspace_id: int) -> InventorySyncResult:
        """Collect and store the inventory; the outcome is recorded on the
        connection either way, and errors are re-raised for the job."""
        credentials = self._credentials(connection_id, workspace_id)
        try:
            snapshot = self._source_factory(credentials).collect()
            result = InventorySync(SqlInventoryRepository(self._session_factory)).apply(connection_id, workspace_id, snapshot)
        except Exception as exc:  # recorded for the UI, then propagated
            self._record(connection_id, "error", str(exc))
            raise
        self._record(connection_id, "ok", result.summary())
        logger.info("Inventory connection #%d synced: %s", connection_id, result.summary())
        return result

    def _credentials(self, connection_id: int, workspace_id: int) -> EntraAppCredentials:
        with self._session_factory() as db:
            connection = _connection(db, workspace_id, connection_id)
            if connection is None:
                raise ConnectionNotFoundError(f"Inventory connection #{connection_id} not found")
            return credentials_of(connection, self._decrypt)

    def _record(self, connection_id: int, status: str, message: str) -> None:
        with self._session_factory() as db:
            connection = db.get(models.InventoryConnection, connection_id)
            if connection is None:
                return
            connection.last_sync_status = status
            connection.last_sync_message = message[:_MAX_STATUS_MESSAGE]
            if status == "ok":
                connection.last_sync_at = self._clock()
            db.commit()


def _connection(db: Session, workspace_id: int, connection_id: int) -> models.InventoryConnection | None:
    return (
        db.query(models.InventoryConnection)
        .filter(models.InventoryConnection.workspace_id == workspace_id, models.InventoryConnection.id == connection_id)
        .first()
    )
