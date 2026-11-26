"""
Purge before the MSP switch-over: every client's data and every account go,
except the default admin (a global admin) and the reference data shared by
all clients (CVE catalog, KEV/EPSS/NVD datasets, platform settings).

    python -m app.purge          # shows what would be deleted
    python -m app.purge --yes    # deletes it

Stop the backend and the workers first, and back up the database. Ids are
not reset: a client created afterwards never reuses an old client's id, so
nothing left elsewhere (graph, files) can be attached to it.

After the purge the platform holds one empty client (DEFAULT_WORKSPACE) and
the default admin, who creates the clients and accounts from Access.
"""
from __future__ import annotations

import argparse
import logging
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import models
from app.db.session import Base

logger = logging.getLogger("v0cday.purge")

# Reference data shared by every client: kept.
KEPT_TABLES = frozenset({"cve_catalog", "cve_cpe_matches", "cve_datasets", "cve_sync_state", "platform_settings"})


@dataclass
class PurgePlan:
    rows: dict[str, int] = field(default_factory=dict)  # table → rows to delete
    kept_admin: str | None = None

    @property
    def total(self) -> int:
        return sum(self.rows.values())


def purged_tables() -> list:
    """Tables to empty, children before parents."""
    return [table for table in reversed(Base.metadata.sorted_tables) if table.name not in KEPT_TABLES]


def plan(db: Session, admin_email: str) -> PurgePlan:
    result = PurgePlan()
    for table in purged_tables():
        query = select(func.count()).select_from(table)
        if table.name == "users":
            query = query.where(table.c.email != admin_email)
        count = db.execute(query).scalar_one()
        if count:
            result.rows[table.name] = count
    admin = db.query(models.User).filter(models.User.email == admin_email).first()
    result.kept_admin = admin.email if admin else None
    return result


def purge(db: Session, admin_email: str, first_client_name: str) -> PurgePlan:
    """Delete everything but the reference data and the default admin, then
    open one empty client. One transaction: all or nothing."""
    done = plan(db, admin_email)
    for table in purged_tables():
        statement = table.delete()
        if table.name == "users":
            statement = statement.where(table.c.email != admin_email)
        db.execute(statement)
    admin = db.query(models.User).filter(models.User.email == admin_email).first()
    if admin is not None:
        admin.is_global_admin = True
    db.add(models.Workspace(name=first_client_name))
    db.commit()
    return done


def purge_graph(uri: str, user: str, password: str) -> bool:
    """The attack graph only holds client data: empty it. False when Neo4j
    cannot be reached (the purge of the database still stands)."""
    try:
        from neo4j import GraphDatabase

        with GraphDatabase.driver(uri, auth=(user, password)) as driver, driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
        return True
    except Exception as exc:  # optional service
        logger.warning("Neo4j not purged (%s): %s", type(exc).__name__, exc)
        return False


def purge_reports(reports_dir: str) -> int:
    """Generated reports hold client data: delete them. Returns the count."""
    directory = Path(reports_dir)
    if not directory.is_dir():
        return 0
    removed = 0
    for entry in directory.iterdir():
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
        removed += 1
    return removed


def purge_queues(redis_url: str) -> bool:
    """Queued jobs and caches name old clients: flush the app's Redis database."""
    try:
        from redis import Redis

        Redis.from_url(redis_url, socket_connect_timeout=3).flushdb()
        return True
    except Exception as exc:
        logger.warning("Redis not flushed (%s): %s", type(exc).__name__, exc)
        return False


def main(argv: list[str] | None = None) -> int:
    from app.core.config import settings
    from app.db.session import SessionLocal

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--yes", action="store_true", help="really delete (otherwise only show what would go)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    with SessionLocal() as db:
        preview = plan(db, settings.DEFAULT_ADMIN_EMAIL)
        print(f"Kept: reference data ({', '.join(sorted(KEPT_TABLES))}) and the account {settings.DEFAULT_ADMIN_EMAIL}"
              + ("" if preview.kept_admin else " (not found: it is created at the next start)"))
        print(f"To delete: {preview.total} rows")
        for table, count in sorted(preview.rows.items()):
            print(f"  {table:28} {count}")
        if not args.yes:
            print("\nNothing deleted. Run again with --yes to purge (backend and workers stopped, database backed up).")
            return 0
        purge(db, settings.DEFAULT_ADMIN_EMAIL, settings.DEFAULT_WORKSPACE)

    graph = purge_graph(settings.NEO4J_URI, settings.NEO4J_USER, settings.NEO4J_PASSWORD)
    reports = purge_reports(settings.REPORTS_DIR)
    queues = purge_queues(settings.REDIS_URL)
    print(f"\nPurged: {preview.total} rows; graph {'emptied' if graph else 'NOT emptied'}; "
          f"{reports} report file(s) deleted; job queues {'flushed' if queues else 'NOT flushed'}.")
    print(f"One empty client '{settings.DEFAULT_WORKSPACE}' and the global admin {settings.DEFAULT_ADMIN_EMAIL} remain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
