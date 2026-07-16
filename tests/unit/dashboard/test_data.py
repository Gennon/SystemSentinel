from __future__ import annotations

from datetime import UTC, datetime
import json

import pytest

from system_sentinel.dashboard.data import load_dashboard_snapshot
from system_sentinel.db.connection import DatabaseConnection


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.mark.asyncio
async def test_load_dashboard_snapshot_returns_latest_metrics_alerts_and_audit(
    db: DatabaseConnection,
) -> None:
    now = datetime.now(UTC).isoformat()

    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (now, "cpu", json.dumps({"overall_percent": 96.0})),
    )
    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (now, "ram", json.dumps({"percent": 70.0})),
    )
    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (
            now,
            "gpu",
            json.dumps(
                {
                    "utilization_percent": 80.0,
                    "peak_utilization_percent": 80.0,
                    "temperature_c": 65.0,
                }
            ),
        ),
    )
    await db.connection.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'alert_fired', 'monitor:cpu', 'CPU threshold exceeded', 'success', ?)
        """,
        (now, json.dumps({"severity": "critical"})),
    )
    await db.connection.commit()

    snapshot = await load_dashboard_snapshot(
        db=db,
        config={"monitors": {"cpu": {"alert_threshold_percent": 90}}},
        audit_limit=10,
    )

    assert "cpu" in snapshot.metrics
    assert "ram" in snapshot.metrics
    assert "gpu" in snapshot.metrics
    assert any(line.startswith("CPU high:") for line in snapshot.active_alerts)
    assert len(snapshot.audit_entries) == 1
    assert snapshot.audit_entries[0].description == "CPU threshold exceeded"


@pytest.mark.asyncio
async def test_load_dashboard_snapshot_handles_empty_tables(db: DatabaseConnection) -> None:
    snapshot = await load_dashboard_snapshot(db=db, config={}, audit_limit=10)

    assert snapshot.metrics == {}
    assert snapshot.active_alerts == []
    assert snapshot.audit_entries == []
