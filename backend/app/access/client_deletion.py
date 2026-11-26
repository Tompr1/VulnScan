"""
Deleting a client for good: the client and every row that belongs to it.

A row belongs to the client when its table has a workspace_id equal to the
client, or when it hangs from such a row by a foreign key (a device's apps
and changes, an inventory audit run…). Reference data shared by every
client (CVE catalog, datasets, platform settings) and the accounts are
never touched: an account only loses its grants on the deleted client.
"""
from __future__ import annotations

from sqlalchemy import Table, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.db.session import Base

# Tables never deleted with a client, even when a foreign key points to it.
_NEVER = frozenset({"workspaces", "users", "user_groups", "client_groups",
                    "cve_catalog", "cve_cpe_matches", "cve_datasets", "cve_sync_state", "platform_settings"})


def _owned(table: Table, client_id: int, seen: tuple[str, ...] = ()) -> ColumnElement | None:
    """Condition selecting the client's rows of `table`, None when the table
    holds none of them."""
    if table.name in _NEVER or table.name in seen:
        return None
    if "workspace_id" in table.c:
        return table.c.workspace_id == client_id
    links = []
    for fk in table.foreign_keys:
        parent = fk.column.table
        condition = _owned(parent, client_id, seen + (table.name,))
        if condition is not None:
            links.append(fk.parent.in_(select(fk.column).where(condition)))
    return or_(*links) if links else None


def _client_tables(client_id: int) -> list[tuple[Table, ColumnElement]]:
    """The client's tables with their condition, children before parents."""
    found = []
    for table in reversed(Base.metadata.sorted_tables):
        condition = _owned(table, client_id)
        if condition is not None:
            found.append((table, condition))
    return found


def client_rows(db: Session, client_id: int) -> dict[str, int]:
    """Rows that deleting the client deletes, by table (only non-empty ones)."""
    rows = {}
    for table, condition in _client_tables(client_id):
        count = db.execute(select(func.count()).select_from(table).where(condition)).scalar_one()
        if count:
            rows[table.name] = count
    return rows


def delete_client_rows(db: Session, client_id: int) -> dict[str, int]:
    """Delete every row of the client, children first, then the client
    itself. The caller commits: all or nothing."""
    deleted = client_rows(db, client_id)
    for table, condition in _client_tables(client_id):
        db.execute(table.delete().where(condition))
    workspaces = Base.metadata.tables["workspaces"]
    db.execute(workspaces.delete().where(workspaces.c.id == client_id))
    return deleted
