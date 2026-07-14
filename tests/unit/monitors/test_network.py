from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.network import NetworkMonitor


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


def _make_counters(bytes_sent: int, bytes_recv: int) -> MagicMock:
    m = MagicMock()
    m.bytes_sent = bytes_sent
    m.bytes_recv = bytes_recv
    return m


@pytest.fixture
def default_config() -> dict:
    return {"enabled": True}


@pytest.mark.asyncio
async def test_first_collect_establishes_baseline_no_insert(
    repo: MetricsRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = NetworkMonitor(default_config, ctx, metrics_repo=repo)

    with patch("psutil.net_io_counters", return_value=_make_counters(1000, 2000)):
        await monitor.collect()

    from datetime import UTC, datetime, timedelta

    results = await repo.query_range("network", since=datetime.now(UTC) - timedelta(seconds=5))
    assert results == []


@pytest.mark.asyncio
async def test_second_collect_inserts_delta(repo: MetricsRepository, default_config: dict) -> None:
    ctx = _make_ctx()
    monitor = NetworkMonitor(default_config, ctx, metrics_repo=repo)

    with patch("psutil.net_io_counters", return_value=_make_counters(1000, 2000)):
        await monitor.collect()  # baseline

    with patch("psutil.net_io_counters", return_value=_make_counters(1500, 3000)):
        await monitor.collect()  # delta

    from datetime import UTC, datetime, timedelta

    results = await repo.query_range("network", since=datetime.now(UTC) - timedelta(seconds=5))
    assert len(results) == 1
    assert results[0]["bytes_sent"] == 500
    assert results[0]["bytes_recv"] == 1000


@pytest.mark.asyncio
async def test_collect_handles_counter_reset(repo: MetricsRepository, default_config: dict) -> None:
    """If counters go backwards (interface bounced), use absolute value."""
    ctx = _make_ctx()
    monitor = NetworkMonitor(default_config, ctx, metrics_repo=repo)

    with patch("psutil.net_io_counters", return_value=_make_counters(5000, 8000)):
        await monitor.collect()

    with patch("psutil.net_io_counters", return_value=_make_counters(100, 200)):
        await monitor.collect()

    from datetime import UTC, datetime, timedelta

    results = await repo.query_range("network", since=datetime.now(UTC) - timedelta(seconds=5))
    assert results[0]["bytes_sent"] == 100
    assert results[0]["bytes_recv"] == 200


@pytest.mark.asyncio
async def test_collect_handles_psutil_failure_gracefully(
    repo: MetricsRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = NetworkMonitor(default_config, ctx, metrics_repo=repo)

    with patch("psutil.net_io_counters", side_effect=RuntimeError("psutil error")):
        await monitor.collect()  # must not raise


@pytest.mark.asyncio
async def test_collect_emits_network_alert_when_threshold_exceeded(
    repo: MetricsRepository,
) -> None:
    ctx = _make_ctx()
    monitor = NetworkMonitor(
        {
            "enabled": True,
            "alert_threshold_bytes_sent": 400,
            "alert_threshold_bytes_recv": 900,
            "alert_cooldown": "00:30:00",
        },
        ctx,
        metrics_repo=repo,
    )

    with patch("psutil.net_io_counters", return_value=_make_counters(1000, 2000)):
        await monitor.collect()  # baseline

    with patch("psutil.net_io_counters", return_value=_make_counters(1500, 3000)):
        await monitor.collect()  # delta: sent=500 recv=1000

    ctx.event_bus.publish.assert_awaited_once()
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.network.throughput_threshold_exceeded"
    assert payload["event_type"] == "network_throughput_threshold_exceeded"
    assert payload["bytes_sent"] == 500
    assert payload["bytes_recv"] == 1000
    assert payload["threshold"] == "sent>400 B/interval or recv>900 B/interval"
    assert payload["triggered_metrics"] == ["bytes_sent", "bytes_recv"]
    assert "timestamp" in payload
    assert "hostname" in payload


@pytest.mark.asyncio
async def test_collect_does_not_emit_network_alert_below_thresholds(
    repo: MetricsRepository,
) -> None:
    ctx = _make_ctx()
    monitor = NetworkMonitor(
        {
            "enabled": True,
            "alert_threshold_bytes_sent": 5_000,
            "alert_threshold_bytes_recv": 5_000,
            "alert_cooldown": "00:30:00",
        },
        ctx,
        metrics_repo=repo,
    )

    with patch("psutil.net_io_counters", return_value=_make_counters(1000, 2000)):
        await monitor.collect()  # baseline

    with patch("psutil.net_io_counters", return_value=_make_counters(1500, 2400)):
        await monitor.collect()  # delta: sent=500 recv=400

    ctx.event_bus.publish.assert_not_awaited()
