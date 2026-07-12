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
    return {
        "enabled": True,
        "alert_threshold_percent": 90,
        "alert_consecutive_intervals": 2,
        "alert_cooldown": "00:30:00",
    }


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


@pytest.mark.asyncio
async def test_collect_emits_cpu_alert_after_required_consecutive_intervals(
    repo: MetricsRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = CpuMonitor(default_config, ctx, metrics_repo=repo)
    high = {"overall_percent": 95.0, "per_core_percent": [95.0]}
    with patch.object(monitor, "_sample", side_effect=[high, high, high]):
        await monitor.collect()
        await monitor.collect()
        await monitor.collect()

    ctx.event_bus.publish.assert_awaited_once()
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.cpu.threshold_exceeded"
    assert payload["event_type"] == "cpu_threshold_exceeded"
    assert payload["current_value"] == "95.0%"
    assert "threshold" in payload
    assert "timestamp" in payload
    assert "hostname" in payload
