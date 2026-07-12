from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.db.login_repository import LoginRepository
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.daily_digest import DailyDigestMonitor


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def metrics_repo(db: DatabaseConnection) -> MetricsRepository:
    return MetricsRepository(db)


@pytest.fixture
async def login_repo(db: DatabaseConnection) -> LoginRepository:
    return LoginRepository(db)


@pytest.fixture
async def conn_repo(db: DatabaseConnection) -> ConnectionRepository:
    return ConnectionRepository(db)


def _make_ctx() -> AppContext:
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=AsyncMock(),
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


@pytest.mark.asyncio
async def test_collect_publishes_single_daily_digest_once_per_local_day(
    db: DatabaseConnection,
    metrics_repo: MetricsRepository,
    login_repo: LoginRepository,
    conn_repo: ConnectionRepository,
) -> None:
    now = datetime(2024, 1, 1, 8, 0, tzinfo=UTC)
    await metrics_repo.insert(
        "cpu",
        {"overall_percent": 25.0, "per_core_percent": [25.0], "top_processes": []},
        timestamp=now - timedelta(hours=1),
    )
    await login_repo.record(ip_address="1.2.3.4", username="root", timestamp=now, port=22)
    await conn_repo.record_attempt("8.8.8.8", 22, "tcp", now)
    await db.connection.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'tool_run', 'scheduler', 'Security update completed. 2 package(s) upgraded.',
                'success', '{"packages_upgraded": ["curl", "openssl"]}')
        """,
        ((now - timedelta(hours=2)).isoformat(),),
    )
    await db.connection.commit()

    ctx = _make_ctx()
    monitor = DailyDigestMonitor(
        {"enabled": True, "send_time_local": "08:00"},
        ctx,
        db=db,
        metrics_repo=metrics_repo,
        login_repo=login_repo,
        connection_repo=conn_repo,
    )

    with (
        patch.object(monitor, "_now_local", return_value=now),
        patch.object(monitor, "_now_utc", return_value=now),
    ):
        await monitor.collect()
        await monitor.collect()

    assert ctx.event_bus.publish.call_count == 1
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.system.daily_digest"
    assert payload["generated_at"] == now.isoformat()
    sections = payload["sections"]
    assert "System Uptime" in sections
    assert "Update Status" in sections
    assert "24h Resource Usage" in sections
    assert "Failed SSH Logins (24h)" in sections
    assert "Unknown Inbound IPs (24h)" in sections
    assert "Files Auto-Deleted (24h)" in sections
    assert "Alerts Since Last Digest" in sections


@pytest.mark.asyncio
async def test_collect_notes_data_gap_when_metrics_are_sparse(
    db: DatabaseConnection,
    metrics_repo: MetricsRepository,
    login_repo: LoginRepository,
    conn_repo: ConnectionRepository,
) -> None:
    now = datetime(2024, 1, 2, 8, 0, tzinfo=UTC)
    await metrics_repo.insert(
        "cpu",
        {"overall_percent": 30.0, "per_core_percent": [30.0], "top_processes": []},
        timestamp=now - timedelta(hours=23, minutes=59),
    )

    ctx = _make_ctx()
    monitor = DailyDigestMonitor(
        {"enabled": True, "send_time_local": "08:00"},
        ctx,
        db=db,
        metrics_repo=metrics_repo,
        login_repo=login_repo,
        connection_repo=conn_repo,
    )

    with (
        patch.object(monitor, "_now_local", return_value=now),
        patch.object(monitor, "_now_utc", return_value=now),
    ):
        await monitor.collect()

    payload = ctx.event_bus.publish.call_args.args[1]
    assert "gap" in payload["sections"]["24h Resource Usage"].lower()
