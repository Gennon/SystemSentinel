from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.cpu import CpuMonitor


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> MetricsRepository:
    return MetricsRepository(db)


def _make_ctx() -> AppContext:
    return AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )


@pytest.fixture
def default_config() -> dict:
    return {"enabled": True}


@pytest.mark.asyncio
async def test_collect_inserts_cpu_record(repo: MetricsRepository, default_config: dict) -> None:
    ctx = _make_ctx()
    monitor = CpuMonitor(default_config, ctx, metrics_repo=repo)

    fake_sample = {"overall_percent": 25.0, "per_core_percent": [20.0, 30.0]}
    with patch.object(monitor, "_sample", return_value=fake_sample):
        await monitor.collect()

    from datetime import UTC, datetime, timedelta

    results = await repo.query_range("cpu", since=datetime.now(UTC) - timedelta(seconds=5))
    assert len(results) == 1
    assert results[0]["overall_percent"] == 25.0
    assert results[0]["per_core_percent"] == [20.0, 30.0]


@pytest.mark.asyncio
async def test_collect_handles_sample_failure_gracefully(
    repo: MetricsRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = CpuMonitor(default_config, ctx, metrics_repo=repo)

    with patch.object(monitor, "_sample", side_effect=RuntimeError("psutil error")):
        await monitor.collect()  # must not raise

    from datetime import UTC, datetime, timedelta

    results = await repo.query_range("cpu", since=datetime.now(UTC) - timedelta(seconds=5))
    assert results == []


@pytest.mark.asyncio
async def test_collect_handles_persist_failure_gracefully(
    default_config: dict,
) -> None:
    ctx = _make_ctx()
    failing_repo = AsyncMock()
    failing_repo.insert = AsyncMock(side_effect=RuntimeError("db error"))

    monitor = CpuMonitor(default_config, ctx, metrics_repo=failing_repo)  # type: ignore[arg-type]

    fake_sample = {"overall_percent": 10.0, "per_core_percent": [10.0]}
    with patch.object(monitor, "_sample", return_value=fake_sample):
        await monitor.collect()  # must not raise
