from __future__ import annotations

from datetime import UTC, datetime
import json

import pytest

from system_sentinel.chat.command_metrics import get_active_alert_conditions
from system_sentinel.db.connection import DatabaseConnection


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.mark.asyncio
async def test_get_active_alert_conditions_includes_gpu_thresholds(db: DatabaseConnection) -> None:
    await db.connection.execute(
        """
        INSERT INTO system_metrics (timestamp, metric_type, data_json)
        VALUES (?, 'gpu', ?)
        """,
        (
            datetime.now(UTC).isoformat(),
            json.dumps(
                {
                    "vendor": "nvidia",
                    "utilization_percent": 96.0,
                    "peak_utilization_percent": 96.0,
                    "temperature_c": 86.0,
                    "power_draw_w": 180.0,
                    "vram_used_mb": 7000.0,
                    "vram_total_mb": 12288.0,
                    "device_count": 1,
                    "gpus": [],
                }
            ),
        ),
    )
    await db.connection.commit()

    conditions = await get_active_alert_conditions(
        config={
            "monitors": {
                "gpu": {
                    "alert_threshold_utilization_percent": 95,
                    "alert_threshold_temperature_c": 85,
                }
            }
        },
        db=db,
        now_iso=datetime.now(UTC).isoformat(),
    )

    assert any("GPU utilization high" in line for line in conditions)
    assert any("GPU temperature high" in line for line in conditions)
