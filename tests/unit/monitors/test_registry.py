from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from importlib.metadata import EntryPoint
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.registry import MonitorRegistry


def _make_ctx() -> AppContext:
    return AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )


def _make_repo() -> MetricsRepository:
    repo = AsyncMock(spec=MetricsRepository)
    repo.purge_old = AsyncMock(return_value=0)
    return repo


def _mock_monitor(name: str, *, enabled: bool = True) -> MagicMock:
    m = AsyncMock()
    m.name = name
    m.is_enabled = MagicMock(return_value=enabled)  # is_enabled is synchronous
    return m


def _mock_entry_point(name: str, cls: type) -> MagicMock:
    ep = MagicMock(spec=EntryPoint)
    ep.name = name
    ep.load.return_value = cls
    return ep


@pytest.fixture
def app_ctx() -> AppContext:
    return _make_ctx()


@pytest.fixture
def metrics_repo() -> MetricsRepository:
    return _make_repo()


class TestDiscover:
    def test_loads_enabled_monitor(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"cpu": {"enabled": True}}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        mock_cls = MagicMock(return_value=MagicMock())
        ep = _mock_entry_point("cpu", mock_cls)

        with patch("system_sentinel.monitors.registry.entry_points", return_value=[ep]):
            registry.discover()

        assert len(registry.monitors) == 1
        mock_cls.assert_called_once_with({"enabled": True}, app_ctx)

    def test_skips_disabled_monitor(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"ram": {"enabled": False}}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        ep = _mock_entry_point("ram", MagicMock())

        with patch("system_sentinel.monitors.registry.entry_points", return_value=[ep]):
            registry.discover()

        assert len(registry.monitors) == 0

    def test_defaults_to_enabled_when_no_config(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config: dict = {}  # no per-monitor config → default enabled=True
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        mock_cls = MagicMock(return_value=MagicMock())
        ep = _mock_entry_point("cpu", mock_cls)

        with patch("system_sentinel.monitors.registry.entry_points", return_value=[ep]):
            registry.discover()

        assert len(registry.monitors) == 1

    def test_continues_after_load_failure(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"cpu": {"enabled": True}, "ram": {"enabled": True}}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        bad_ep = MagicMock(spec=EntryPoint)
        bad_ep.name = "cpu"
        bad_ep.load.side_effect = ImportError("missing dep")

        good_cls = MagicMock(return_value=MagicMock())
        good_ep = _mock_entry_point("ram", good_cls)

        with patch(
            "system_sentinel.monitors.registry.entry_points", return_value=[bad_ep, good_ep]
        ):
            registry.discover()  # must not raise

        assert len(registry.monitors) == 1

    def test_monitors_property_returns_copy(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"cpu": {"enabled": True}}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)
        mock_cls = MagicMock(return_value=MagicMock())
        ep = _mock_entry_point("cpu", mock_cls)

        with patch("system_sentinel.monitors.registry.entry_points", return_value=[ep]):
            registry.discover()

        monitors = registry.monitors
        monitors.clear()
        assert len(registry.monitors) == 1  # original list unaffected


class TestCollectionLoop:
    @pytest.mark.asyncio
    async def test_collect_called_on_start(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 0.05, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)
        monitor = _mock_monitor("cpu")
        registry._monitors.append(monitor)

        await registry.start()
        await asyncio.sleep(0.15)
        await registry.stop()

        assert monitor.collect.call_count >= 1

    @pytest.mark.asyncio
    async def test_disabled_monitor_not_collected(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 0.05, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)
        monitor = _mock_monitor("cpu", enabled=False)
        registry._monitors.append(monitor)

        await registry.start()
        await asyncio.sleep(0.15)
        await registry.stop()

        monitor.collect.assert_not_called()

    @pytest.mark.asyncio
    async def test_collection_task_cancelled_on_stop(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 60, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        await registry.start()
        assert registry._collection_task is not None
        assert not registry._collection_task.done()

        await registry.stop()
        assert registry._collection_task.done()

    @pytest.mark.asyncio
    async def test_monitor_exception_does_not_stop_loop(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 0.05, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        bad_monitor = _mock_monitor("bad")
        bad_monitor.collect.side_effect = RuntimeError("unexpected crash")

        ok_monitor = _mock_monitor("ok")
        registry._monitors.extend([bad_monitor, ok_monitor])

        await registry.start()
        await asyncio.sleep(0.15)
        await registry.stop()

        assert ok_monitor.collect.call_count >= 1

    @pytest.mark.asyncio
    async def test_collects_multiple_times_per_interval(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 0.04, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)
        monitor = _mock_monitor("cpu")
        registry._monitors.append(monitor)

        await registry.start()
        await asyncio.sleep(0.2)
        await registry.stop()

        # With a 40ms interval, 200ms should yield at least 2 collections
        assert monitor.collect.call_count >= 2


class TestPurgeLoop:
    @pytest.mark.asyncio
    async def test_purge_runs_on_startup(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 60, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        await registry.start()
        await asyncio.sleep(0.05)
        await registry.stop()

        metrics_repo.purge_old.assert_called_once()

    @pytest.mark.asyncio
    async def test_purge_passes_none_metric_type(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 60, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        await registry.start()
        await asyncio.sleep(0.05)
        await registry.stop()

        call_args = metrics_repo.purge_old.call_args
        assert call_args.args[0] is None  # purge all metric types

    @pytest.mark.asyncio
    async def test_purge_respects_retention_days_config(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 60, "retention_days": 7}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        await registry.start()
        await asyncio.sleep(0.05)
        await registry.stop()

        call_args = metrics_repo.purge_old.call_args
        cutoff: datetime = call_args.args[1]
        expected = datetime.now(UTC) - timedelta(days=7)
        assert abs((cutoff - expected).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_purge_exception_does_not_crash_loop(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        metrics_repo.purge_old = AsyncMock(side_effect=RuntimeError("db error"))
        config = {"collection_interval_seconds": 0.05, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        await registry.start()
        await asyncio.sleep(0.1)
        await registry.stop()  # must not raise

    @pytest.mark.asyncio
    async def test_purge_task_cancelled_on_stop(
        self, app_ctx: AppContext, metrics_repo: MetricsRepository
    ) -> None:
        config = {"collection_interval_seconds": 60, "retention_days": 30}
        registry = MonitorRegistry(config, app_ctx, metrics_repo)

        await registry.start()
        assert registry._purge_task is not None

        await registry.stop()
        assert registry._purge_task.done()
