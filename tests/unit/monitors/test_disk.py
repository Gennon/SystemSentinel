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
    return {
        "enabled": True,
        "alert_threshold_percent": 85,
        "alert_cooldown": "00:30:00",
    }


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


@pytest.mark.asyncio
async def test_collect_emits_disk_alert_when_threshold_exceeded(
    repo: MetricsRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = DiskMonitor(default_config, ctx, metrics_repo=repo)
    high_sample = {
        "partitions": [
            {
                "mountpoint": "/",
                "device": "/dev/sda1",
                "fstype": "ext4",
                "total_bytes": 100_000_000_000,
                "used_bytes": 91_000_000_000,
                "free_bytes": 9_000_000_000,
                "percent": 91.0,
            }
        ]
    }
    with patch.object(monitor, "_sample", return_value=high_sample):
        await monitor.collect()

    ctx.event_bus.publish.assert_awaited_once()
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.disk.threshold_exceeded"
    assert payload["event_type"] == "disk_threshold_exceeded"
    assert payload["current_value"] == "91.0%"
    assert payload["threshold"] == ">85.0%"
    assert payload["mountpoint"] == "/"
    assert payload["device"] == "/dev/sda1"
    assert "timestamp" in payload
    assert "hostname" in payload
