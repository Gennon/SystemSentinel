from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
import subprocess
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.gpu import GpuMonitor


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


def _completed(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.mark.asyncio
async def test_collect_inserts_gpu_record_with_nvidia_backend(repo: MetricsRepository) -> None:
    ctx = _make_ctx()
    monitor = GpuMonitor({"enabled": True}, ctx, metrics_repo=repo)

    def _run_side_effect(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if "--query-gpu=index" in cmd:
            return _completed(stdout="0\n")
        return _completed(stdout="42, 8000, 16384, 73, 145\n")

    with (
        patch("system_sentinel.monitors.gpu.shutil.which", return_value="/usr/bin/nvidia-smi"),
        patch("system_sentinel.monitors.gpu.subprocess.run", side_effect=_run_side_effect),
    ):
        await monitor.collect()

    results = await repo.query_range("gpu", since=datetime.now(UTC) - timedelta(seconds=5))
    assert len(results) == 1
    assert results[0]["vendor"] == "nvidia"
    assert results[0]["device_count"] == 1
    assert results[0]["utilization_percent"] == pytest.approx(42.0)
    assert results[0]["vram_used_mb"] == pytest.approx(8000.0)
    assert results[0]["vram_total_mb"] == pytest.approx(16384.0)
    assert results[0]["temperature_c"] == pytest.approx(73.0)
    assert results[0]["power_draw_w"] == pytest.approx(145.0)


@pytest.mark.asyncio
async def test_collect_emits_gpu_alert_when_threshold_exceeded(repo: MetricsRepository) -> None:
    ctx = _make_ctx()
    monitor = GpuMonitor(
        {
            "enabled": True,
            "alert_threshold_utilization_percent": 95,
            "alert_threshold_temperature_c": 85,
            "alert_cooldown": "00:30:00",
        },
        ctx,
        metrics_repo=repo,
    )

    def _run_side_effect(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if "--query-gpu=index" in cmd:
            return _completed(stdout="0\n")
        return _completed(stdout="98, 9000, 16384, 88, 170\n")

    with (
        patch("system_sentinel.monitors.gpu.shutil.which", return_value="/usr/bin/nvidia-smi"),
        patch("system_sentinel.monitors.gpu.subprocess.run", side_effect=_run_side_effect),
    ):
        await monitor.collect()

    ctx.event_bus.publish.assert_awaited_once()
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.gpu.threshold_exceeded"
    assert payload["event_type"] == "gpu_threshold_exceeded"
    assert payload["current_utilization_percent"] == "98.0%"
    assert payload["current_temperature_c"] == "88.0°C"
    assert payload["triggered_metrics"] == ["utilization", "temperature"]
    assert payload["threshold"] == "util>95.0% or temp>85.0°C"
    assert payload["vendor"] == "nvidia"
    assert "timestamp" in payload
    assert "hostname" in payload


@pytest.mark.asyncio
async def test_collect_skips_when_no_supported_gpu_tool_is_available(
    repo: MetricsRepository,
) -> None:
    ctx = _make_ctx()
    monitor = GpuMonitor({"enabled": True}, ctx, metrics_repo=repo)

    with patch("system_sentinel.monitors.gpu.shutil.which", return_value=None):
        await monitor.collect()

    results = await repo.query_range("gpu", since=datetime.now(UTC) - timedelta(seconds=5))
    assert results == []
    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_inserts_gpu_record_with_amd_backend(repo: MetricsRepository) -> None:
    ctx = _make_ctx()
    monitor = GpuMonitor({"enabled": True}, ctx, metrics_repo=repo)

    def _which_side_effect(command: str) -> str | None:
        if command == "nvidia-smi":
            return None
        if command == "rocm-smi":
            return "/usr/bin/rocm-smi"
        return None

    def _run_side_effect(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        _ = kwargs
        if "--showid" in cmd:
            return _completed(stdout='{"card0": {"GPU ID": "0x744c"}}')
        return _completed(
            stdout=(
                '{"card0": {'
                '"GPU use (%)": "67", '
                '"GPU memory use (%)": "25", '
                '"Total VRAM Memory (B)": "17179869184", '
                '"Temperature (Sensor edge) (C)": "71.5", '
                '"Average Graphics Package Power (W)": "182.0"'
                "}}"
            )
        )

    with (
        patch("system_sentinel.monitors.gpu.shutil.which", side_effect=_which_side_effect),
        patch("system_sentinel.monitors.gpu.subprocess.run", side_effect=_run_side_effect),
    ):
        await monitor.collect()

    results = await repo.query_range("gpu", since=datetime.now(UTC) - timedelta(seconds=5))
    assert len(results) == 1
    assert results[0]["vendor"] == "amd"
    assert results[0]["device_count"] == 1
    assert results[0]["utilization_percent"] == pytest.approx(67.0)
    assert results[0]["temperature_c"] == pytest.approx(71.5)
