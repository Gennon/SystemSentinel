from __future__ import annotations

from datetime import UTC, datetime

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.connection_repository import ConnectionRepository


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> ConnectionRepository:
    return ConnectionRepository(db)


@pytest.mark.asyncio
async def test_get_last_alerted_returns_none_for_unseen(repo: ConnectionRepository) -> None:
    result = await repo.get_last_alerted("1.2.3.4", 22)
    assert result is None


@pytest.mark.asyncio
async def test_upsert_and_get_last_alerted(repo: ConnectionRepository) -> None:
    now = datetime.now(UTC)
    await repo.upsert("1.2.3.4", 22, "tcp", now)
    result = await repo.get_last_alerted("1.2.3.4", 22, "tcp")
    assert result is not None
    assert abs((result - now).total_seconds()) < 1


@pytest.mark.asyncio
async def test_upsert_updates_last_alerted_on_repeat(repo: ConnectionRepository) -> None:
    t1 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    t2 = datetime(2024, 1, 1, 2, 0, 0, tzinfo=UTC)
    await repo.upsert("1.2.3.4", 22, "tcp", t1)
    await repo.upsert("1.2.3.4", 22, "tcp", t2)
    result = await repo.get_last_alerted("1.2.3.4", 22, "tcp")
    assert result is not None
    assert abs((result - t2).total_seconds()) < 1


@pytest.mark.asyncio
async def test_different_ports_are_independent(repo: ConnectionRepository) -> None:
    now = datetime.now(UTC)
    await repo.upsert("1.2.3.4", 22, "tcp", now)
    assert await repo.get_last_alerted("1.2.3.4", 80, "tcp") is None


@pytest.mark.asyncio
async def test_different_ips_are_independent(repo: ConnectionRepository) -> None:
    now = datetime.now(UTC)
    await repo.upsert("1.2.3.4", 22, "tcp", now)
    assert await repo.get_last_alerted("5.6.7.8", 22, "tcp") is None
