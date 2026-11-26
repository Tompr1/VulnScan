import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import models
from app.db.session import Base

# Set to a throwaway PostgreSQL database to run the integration tests on the
# production engine (foreign keys and constraints enforced), e.g.
#   V0CDAY_TEST_DATABASE_URL=postgresql+psycopg2://app:app@127.0.0.1:55432/tests
# Every table of that database is dropped before each test.
POSTGRES_URL = os.environ.get("V0CDAY_TEST_DATABASE_URL")
# Ids the database generates start above the fixed ids tests insert.
_FIRST_GENERATED_ID = 100_000


@pytest.fixture
def session_factory():
    """Fresh database per test (isolated, repeatable): in-memory SQLite, or
    PostgreSQL when V0CDAY_TEST_DATABASE_URL is set."""
    if POSTGRES_URL:
        engine = create_engine(POSTGRES_URL)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        with engine.begin() as connection:
            for (sequence,) in connection.execute(text("SELECT sequencename FROM pg_sequences WHERE schemaname = 'public'")):
                connection.execute(text(f'ALTER SEQUENCE "{sequence}" RESTART WITH {_FIRST_GENERATED_ID}'))
            # Fixtures add parents and children in one commit, in any order:
            # foreign keys are checked at commit, still enforced.
            foreign_keys = connection.execute(text(
                "SELECT conrelid::regclass::text, conname FROM pg_constraint WHERE contype = 'f'"
            )).all()
            for table, constraint in foreign_keys:
                connection.execute(text(f'ALTER TABLE {table} ALTER CONSTRAINT "{constraint}" DEFERRABLE INITIALLY DEFERRED'))
    else:
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, autoflush=False)
    engine.dispose()


@pytest.fixture
def db(session_factory):
    with session_factory() as session:
        yield session


@pytest.fixture
def workspace(db):
    """Two workspaces: tests use #1, #2 checks tenant isolation."""
    db.add_all([models.Workspace(id=1, name="main"), models.Workspace(id=2, name="other")])
    db.add_all([
        models.Profile(id=5, workspace_id=1, name="Default", plugin_selection_json="{}", options_json="{}"),
        models.Profile(id=6, workspace_id=2, name="Other tenant", plugin_selection_json="{}", options_json="{}"),
    ])
    db.commit()
    return 1


@pytest.fixture
def session_de(db):
    """Fabrique de sessions réelles : un compte en base avec un droit sur ce
    client, et les claims de son jeton. Le rôle étant relu en base à chaque
    requête, c'est le droit qui compte, pas le jeton."""

    def ouvrir(ws: int = 1, role: str = "admin", email: str | None = None) -> dict:
        email = email or f"{role}-{ws}@corp.local"
        user = db.query(models.User).filter_by(email=email).first()
        if user is None:
            user = models.User(email=email, password_hash="x")
            db.add(user)
            db.flush()
        db.add(models.AccessGrant(user_id=user.id, workspace_id=ws, role=role))
        db.commit()
        return {"ws": ws, "uid": user.id, "sub": email, "role": role}

    return ouvrir
