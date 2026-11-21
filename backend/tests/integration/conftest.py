import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import models
from app.db.session import Base


@pytest.fixture
def session_factory():
    """Fresh in-memory SQLite database per test (isolated, repeatable)."""
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
