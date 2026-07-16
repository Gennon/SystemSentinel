from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.metrics_repository import MetricsRepository
    from system_sentinel.monitors.base import BaseMonitor

# Purge old metrics once per day.
_PURGE_INTERVAL_SECONDS: int = 24 * 60 * 60


class MonitorRegistry:
    """Discovers, instantiates, and runs monitor plugins.

    The *collection loop* calls every enabled monitor's :py:meth:`collect`
    method on the configured interval (``monitors.collection_interval``,
    HH:MM:SS, default 00:01:00).

    The *purge loop* deletes metric records older than the configured retention
    window (``monitors.retention``, HH:MM:SS or <days>d HH:MM:SS, default 30 days)
    once per day.

    Usage::

        registry = MonitorRegistry(monitors_config, app_ctx, metrics_repo)
        registry.discover()
        await registry.start()
        ...
        await registry.stop()
    """

    _ENTRY_POINT_GROUP = "sentinel.monitors"

    def __init__(
        self,
        monitors_config: dict[str, Any],
        app_ctx: AppContext,
        metrics_repo: MetricsRepository,
    ) -> None:
        self._config = monitors_config
        self._ctx = app_ctx
        self._metrics_repo = metrics_repo
        self._monitors: list[BaseMonitor] = []
        self._logger = app_ctx.logger.getChild("monitor.registry")
        self._collection_task: asyncio.Task[None] | None = None
        self._purge_task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event = asyncio.Event()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> None:
        """Load all enabled monitors registered via the ``sentinel.monitors`` entry-point group."""
        eps = entry_points(group=self._ENTRY_POINT_GROUP)
        global_geoip_database_path = self._config.get("geoip_database_path")
        global_geoip = (
            global_geoip_database_path.strip()
            if isinstance(global_geoip_database_path, str)
            else ""
        )
        for ep in eps:
            raw_monitor_config = self._config.get(ep.name, {})
            monitor_config: dict[str, Any] = (
                dict(raw_monitor_config) if isinstance(raw_monitor_config, dict) else {}
            )
            if global_geoip and "geoip_database_path" not in monitor_config:
                monitor_config["geoip_database_path"] = global_geoip
            if not monitor_config.get("enabled", True):
                self._logger.debug("Monitor %r is disabled — skipping", ep.name)
                continue
            try:
                cls = ep.load()
                monitor: BaseMonitor = cls(monitor_config, self._ctx)
                self._monitors.append(monitor)
                self._logger.info("Loaded monitor: %s", ep.name)
            except Exception:
                self._logger.exception("Failed to load monitor %r", ep.name)

    @property
    def monitors(self) -> list[BaseMonitor]:
        """Return a snapshot of the currently registered monitors."""
        return list(self._monitors)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the collection loop and the daily retention purge loop."""
        self._stop_event.clear()
        interval = parse_duration_from_config(
            self._config,
            key="collection_interval",
            default_seconds=60,
            logger=self._logger,
        )
        retention_seconds = parse_duration_from_config(
            self._config,
            key="retention",
            default_seconds=30 * 24 * 60 * 60,
            logger=self._logger,
        )

        self._collection_task = asyncio.create_task(
            self._collection_loop(interval),
            name="monitor.collection_loop",
        )
        self._purge_task = asyncio.create_task(
            self._purge_loop(retention_seconds),
            name="monitor.purge_loop",
        )
        self._logger.info(
            "Monitor collection loop started (interval=%ds, retention=%ds)",
            int(interval),
            int(retention_seconds),
        )

    async def stop(self) -> None:
        """Signal both loops to stop and wait for them to finish."""
        self._stop_event.set()
        for task in (self._collection_task, self._purge_task):
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        for monitor in self._monitors:
            try:
                await monitor.stop()
            except Exception:
                self._logger.exception("Unexpected error while stopping monitor %r", monitor.name)
        self._logger.info("Monitor collection loop stopped.")

    # ------------------------------------------------------------------
    # Internal loops
    # ------------------------------------------------------------------

    async def _collection_loop(self, interval_seconds: float) -> None:
        """Run all enabled monitors, then sleep for *interval_seconds*."""
        while not self._stop_event.is_set():
            await self._run_all()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval_seconds)

    async def _run_all(self) -> None:
        """Call :py:meth:`collect` on every enabled monitor, logging unexpected errors."""
        for monitor in self._monitors:
            if not monitor.is_enabled():
                continue
            try:
                await monitor.collect()
            except Exception:
                self._logger.exception("Unexpected error in monitor %r — continuing", monitor.name)

    async def _purge_loop(self, retention_seconds: float) -> None:
        """Purge old metric records immediately, then repeat every 24 hours."""
        while not self._stop_event.is_set():
            await self._purge_old_metrics(retention_seconds)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), timeout=_PURGE_INTERVAL_SECONDS)

    async def _purge_old_metrics(self, retention_seconds: float) -> None:
        cutoff = datetime.now(UTC) - timedelta(seconds=retention_seconds)
        try:
            deleted = await self._metrics_repo.purge_old(None, cutoff)
            if deleted:
                self._logger.info(
                    "Purged %d metric record(s) older than %d second(s)",
                    deleted,
                    int(retention_seconds),
                )
        except Exception:
            self._logger.exception("Failed to purge old metrics")
