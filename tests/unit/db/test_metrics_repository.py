from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> MetricsRepository:
    return MetricsRepository(db)


@pytest.mark.asyncio
async def test_insert_and_query_range(repo: MetricsRepository) -> None:
    now = datetime.now(UTC)
    await repo.insert("cpu", {"overall_percent": 42.0}, timestamp=now)

    results = await repo.query_range("cpu", since=now - timedelta(seconds=1))
    assert len(results) == 1
    assert results[0]["overall_percent"] == 42.0
    assert "timestamp" in results[0]


@pytest.mark.asyncio
async def test_query_range_filters_by_type(repo: MetricsRepository) -> None:
    now = datetime.now(UTC)
    await repo.insert("cpu", {"overall_percent": 10.0}, timestamp=now)
    await repo.insert("ram", {"percent": 50.0}, timestamp=now)

    cpu_results = await repo.query_range("cpu", since=now - timedelta(seconds=1))
    ram_results = await repo.query_range("ram", since=now - timedelta(seconds=1))

    assert len(cpu_results) == 1
    assert len(ram_results) == 1
    assert "overall_percent" in cpu_results[0]
    assert "percent" in ram_results[0]


@pytest.mark.asyncio
async def test_query_range_excludes_outside_window(repo: MetricsRepository) -> None:
    old_ts = datetime.now(UTC) - timedelta(hours=2)
    await repo.insert("cpu", {"overall_percent": 5.0}, timestamp=old_ts)

    results = await repo.query_range(
        "cpu",
        since=datetime.now(UTC) - timedelta(minutes=10),
    )
    assert results == []


@pytest.mark.asyncio
async def test_purge_old_removes_stale_rows(repo: MetricsRepository) -> None:
    old_ts = datetime.now(UTC) - timedelta(days=31)
    recent_ts = datetime.now(UTC)
    await repo.insert("cpu", {"overall_percent": 1.0}, timestamp=old_ts)
    await repo.insert("cpu", {"overall_percent": 2.0}, timestamp=recent_ts)

    cutoff = datetime.now(UTC) - timedelta(days=30)
    deleted = await repo.purge_old(None, cutoff)

    assert deleted == 1
    results = await repo.query_range("cpu", since=datetime.now(UTC) - timedelta(days=60))
    assert len(results) == 1
    assert results[0]["overall_percent"] == 2.0


@pytest.mark.asyncio
async def test_purge_old_by_metric_type(repo: MetricsRepository) -> None:
    old_ts = datetime.now(UTC) - timedelta(days=31)
    await repo.insert("cpu", {"overall_percent": 1.0}, timestamp=old_ts)
    await repo.insert("ram", {"percent": 50.0}, timestamp=old_ts)

    cutoff = datetime.now(UTC) - timedelta(days=30)
    deleted = await repo.purge_old("cpu", cutoff)

    assert deleted == 1
    # RAM row should still be present
    ram_results = await repo.query_range("ram", since=old_ts - timedelta(seconds=1))
    assert len(ram_results) == 1


@pytest.mark.asyncio
async def test_query_range_returns_ordered_by_timestamp(repo: MetricsRepository) -> None:
    base = datetime.now(UTC) - timedelta(seconds=10)
    for i in range(3):
        await repo.insert(
            "cpu", {"overall_percent": float(i)}, timestamp=base + timedelta(seconds=i)
        )

    results = await repo.query_range("cpu", since=base - timedelta(seconds=1))
    percents = [r["overall_percent"] for r in results]
    assert percents == [0.0, 1.0, 2.0]
