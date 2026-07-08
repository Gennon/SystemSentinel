from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.disk import DiskMonitor


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


FAKE_SAMPLE = {
    "partitions": [
        {
            "mountpoint": "/",
            "device": "/dev/sda1",
            "fstype": "ext4",
            "total_bytes": 100_000_000_000,
            "used_bytes": 60_000_000_000,
            "free_bytes": 40_000_000_000,
            "percent": 60.0,
        }
    ]
}


@pytest.mark.asyncio
async def test_collect_inserts_disk_record(repo: MetricsRepository, default_config: dict) -> None:
    ctx = _make_ctx()
    monitor = DiskMonitor(default_config, ctx, metrics_repo=repo)

    with patch.object(monitor, "_sample", return_value=FAKE_SAMPLE):
        await monitor.collect()

    from datetime import UTC, datetime, timedelta

    results = await repo.query_range("disk", since=datetime.now(UTC) - timedelta(seconds=5))
    assert len(results) == 1
    assert len(results[0]["partitions"]) == 1
    part = results[0]["partitions"][0]
    assert part["mountpoint"] == "/"
    assert part["percent"] == 60.0


@pytest.mark.asyncio
async def test_collect_handles_failure_gracefully(
    repo: MetricsRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = DiskMonitor(default_config, ctx, metrics_repo=repo)

    with patch.object(monitor, "_sample", side_effect=RuntimeError("psutil error")):
        await monitor.collect()  # must not raise

    from datetime import UTC, datetime, timedelta

    results = await repo.query_range("disk", since=datetime.now(UTC) - timedelta(seconds=5))
    assert results == []
