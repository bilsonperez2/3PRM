"""Shared pytest fixtures.

Tests are split by dependency:
  - Pure-Python tests (domain validation, the scan-authorization gate) need no
    database and always run.
  - Integration tests (tests/api) need a real Postgres — Postgres-specific
    column types (UUID, JSONB) are used throughout the schema by design, so
    SQLite can't stand in. Those tests are decorated with `requires_postgres`
    and skip cleanly if TEST_DATABASE_URL isn't reachable, rather than failing
    the whole suite in environments without a database available.
"""

import os
import socket
import urllib.parse

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models import *  # noqa: F401,F403 (registers all models on Base.metadata)

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+psycopg://tprm:changeme@localhost:5432/tprm_test",
)


def _postgres_reachable(url: str) -> bool:
    parsed = urllib.parse.urlparse(url.replace("+psycopg", ""))
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=1):
            return True
    except OSError:
        return False


requires_postgres = pytest.mark.skipif(
    not _postgres_reachable(TEST_DATABASE_URL),
    reason="No Postgres reachable at TEST_DATABASE_URL — integration tests need a real database.",
)


def _redis_reachable(host: str = "localhost", port: int = 6379) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


requires_celery_broker = pytest.mark.skipif(
    not _redis_reachable(),
    reason="No Redis reachable on localhost:6379 — scan enqueueing needs the Celery broker.",
)


@pytest.fixture(scope="session")
def engine():
    eng = create_engine(TEST_DATABASE_URL)
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture()
def db_session(engine):
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def client(db_session):
    from fastapi.testclient import TestClient

    from app.db.session import get_db
    from app.main import app

    def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
