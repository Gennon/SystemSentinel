from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.monitors.weekly_digest import WeeklyDigestMonitor


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


def _make_ctx() -> AppContext:
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=AsyncMock(),
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


@pytest.mark.asyncio
async def test_collect_publishes_single_weekly_digest_once_per_week(
    db: DatabaseConnection,
) -> None:
    now = datetime(2024, 1, 8, 8, 0, tzinfo=UTC)  # Monday

    await db.connection.executemany(
        """
        INSERT INTO system_metrics (timestamp, metric_type, data_json)
        VALUES (?, ?, ?)
        """,
        [
            (
                (now - timedelta(days=13)).isoformat(),
                "disk",
                json.dumps(
                    {
                        "partitions": [
                            {
                                "mountpoint": "/",
                                "total_bytes": 300,
                                "used_bytes": 100,
                                "free_bytes": 200,
                                "percent": 33.3,
                            }
                        ]
                    }
                ),
            ),
            (
                (now - timedelta(days=8)).isoformat(),
                "disk",
                json.dumps(
                    {
                        "partitions": [
                            {
                                "mountpoint": "/",
                                "total_bytes": 300,
                                "used_bytes": 110,
                                "free_bytes": 190,
                                "percent": 36.7,
                            }
                        ]
                    }
                ),
            ),
            (
                (now - timedelta(days=6)).isoformat(),
                "disk",
                json.dumps(
                    {
                        "partitions": [
                            {
                                "mountpoint": "/",
                                "total_bytes": 300,
                                "used_bytes": 110,
                                "free_bytes": 190,
                                "percent": 36.7,
                            }
                        ]
                    }
                ),
            ),
            (
                (now - timedelta(hours=1)).isoformat(),
                "disk",
                json.dumps(
                    {
                        "partitions": [
                            {
                                "mountpoint": "/",
                                "total_bytes": 300,
                                "used_bytes": 130,
                                "free_bytes": 170,
                                "percent": 43.3,
                            }
                        ]
                    }
                ),
            ),
            (
                (now - timedelta(days=10)).isoformat(),
                "cpu",
                json.dumps(
                    {"overall_percent": 20.0, "per_core_percent": [20.0], "top_processes": []}
                ),
            ),
            (
                (now - timedelta(days=2)).isoformat(),
                "cpu",
                json.dumps(
                    {"overall_percent": 40.0, "per_core_percent": [40.0], "top_processes": []}
                ),
            ),
            ((now - timedelta(days=10)).isoformat(), "ram", json.dumps({"percent": 45.0})),
            ((now - timedelta(days=2)).isoformat(), "ram", json.dumps({"percent": 55.0})),
        ],
    )

    await db.connection.executemany(
        """
        INSERT INTO login_attempts (timestamp, ip_address, username, port, host)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            ((now - timedelta(days=3)).isoformat(), "1.2.3.4", "root", 22, ""),
            ((now - timedelta(days=2)).isoformat(), "5.6.7.8", "ubuntu", 22, ""),
        ],
    )
    await db.connection.execute(
        """
        INSERT INTO login_successes (timestamp, ip_address, username, port, auth_method, host)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ((now - timedelta(days=1)).isoformat(), "9.9.9.9", "alice", 22, "publickey", ""),
    )
    await db.connection.execute(
        """
        INSERT INTO login_anomalies (observed_at, anomaly_type, username, ip_address, details_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        ((now - timedelta(days=2)).isoformat(), "off_hours", "alice", "9.9.9.9", "{}"),
    )
    await db.connection.executemany(
        """
        INSERT INTO audit_log (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'tool_run', 'scheduler', ?, 'success', ?)
        """,
        [
            (
                (now - timedelta(days=2)).isoformat(),
                "Security update completed. 2 package(s) upgraded.",
                json.dumps({"packages_upgraded": ["curl", "openssl"]}),
            ),
            (
                (now - timedelta(days=1)).isoformat(),
                "Hardening audit passed (5/5); remediated 0.",
                json.dumps({"tool": "hardening", "failed_checks": [], "remediated_checks": []}),
            ),
        ],
    )
    await db.connection.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'chat_command', 'chat:discord:123', 'Processed confirmed chat command !cleanup.',
                'success', ?)
        """,
        (
            (now - timedelta(days=1)).isoformat(),
            json.dumps(
                {
                    "command": "!cleanup",
                    "result": "executed",
                    "cleanup": {
                        "deleted_files": 3,
                        "reclaimed_bytes": 4096,
                        "failed_deletions": 0,
                    },
                }
            ),
        ),
    )
    await db.connection.commit()

    ctx = _make_ctx()
    monitor = WeeklyDigestMonitor(
        {"enabled": True, "send_day_local": "monday", "send_time_local": "08:00"},
        ctx,
        db=db,
    )

    with (
        patch.object(monitor, "_now_local", return_value=now),
        patch.object(monitor, "_now_utc", return_value=now),
    ):
        await monitor.collect()
        await monitor.collect()

    assert ctx.event_bus.publish.call_count == 1
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.system.weekly_digest"
    assert payload["generated_at"] == now.isoformat()
    sections = payload["sections"]
    assert "Storage Usage Trend (7d)" in sections
    assert "Login Summary (7d)" in sections
    assert "Resource Averages vs Previous Week" in sections
    assert "Update History (7d)" in sections
    assert "File Cleanup Summary (7d)" in sections
    assert "Security Posture (7d)" in sections
    assert "+" in sections["Storage Usage Trend (7d)"]


@pytest.mark.asyncio
async def test_collect_waits_until_configured_weekday_and_time(db: DatabaseConnection) -> None:
    ctx = _make_ctx()
    monitor = WeeklyDigestMonitor(
        {"enabled": True, "send_day_local": "monday", "send_time_local": "08:00"},
        ctx,
        db=db,
    )

    before_time = datetime(2024, 1, 8, 7, 59, tzinfo=UTC)  # Monday, too early
    wrong_day = datetime(2024, 1, 9, 8, 30, tzinfo=UTC)  # Tuesday

    with (
        patch.object(monitor, "_now_local", side_effect=[before_time, wrong_day]),
        patch.object(monitor, "_now_utc", return_value=before_time),
    ):
        await monitor.collect()
        await monitor.collect()

    ctx.event_bus.publish.assert_not_called()
