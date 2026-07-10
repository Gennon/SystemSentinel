from __future__ import annotations

from datetime import UTC, datetime, timedelta

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


@pytest.mark.asyncio
async def test_get_last_alerted_for_ip_returns_latest_across_ports(
    repo: ConnectionRepository,
) -> None:
    t1 = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    t2 = datetime(2024, 1, 1, 2, 0, 0, tzinfo=UTC)
    await repo.upsert("1.2.3.4", 22, "tcp", t1)
    await repo.upsert("1.2.3.4", 443, "tcp", t2)

    result = await repo.get_last_alerted_for_ip("1.2.3.4", "tcp")
    assert result is not None
    assert abs((result - t2).total_seconds()) < 1


@pytest.mark.asyncio
async def test_record_attempt_and_count_since(repo: ConnectionRepository) -> None:
    now = datetime.now(UTC)
    since = now.replace(microsecond=0)
    await repo.record_attempt("1.2.3.4", 22, "tcp", now)
    await repo.record_attempt("1.2.3.4", 80, "tcp", now)

    count = await repo.count_attempts_since("1.2.3.4", since)
    assert count == 2


@pytest.mark.asyncio
async def test_ports_since_returns_unique_sorted_ports(repo: ConnectionRepository) -> None:
    now = datetime.now(UTC)
    await repo.record_attempt("1.2.3.4", 80, "tcp", now)
    await repo.record_attempt("1.2.3.4", 22, "tcp", now)
    await repo.record_attempt("1.2.3.4", 22, "tcp", now)

    ports = await repo.ports_since("1.2.3.4", now - timedelta(minutes=1))
    assert ports == [22, 80]


@pytest.mark.asyncio
async def test_ip_port_activity_since_groups_rows(repo: ConnectionRepository) -> None:
    now = datetime.now(UTC)
    await repo.record_attempt("1.2.3.4", 22, "tcp", now)
    await repo.record_attempt("1.2.3.4", 22, "tcp", now)
    await repo.record_attempt("5.6.7.8", 80, "tcp", now)

    rows = await repo.ip_port_activity_since(now - timedelta(minutes=1))
    assert rows[0]["ip_address"] == "1.2.3.4"
    assert rows[0]["dest_port"] == 22
    assert rows[0]["attempts"] == 2


@pytest.mark.asyncio
async def test_state_roundtrip(repo: ConnectionRepository) -> None:
    assert await repo.get_state("connections.daily_report.last_sent_date_utc") is None
    await repo.set_state("connections.daily_report.last_sent_date_utc", "2026-07-10")
    value = await repo.get_state("connections.daily_report.last_sent_date_utc")
    assert value == "2026-07-10"
