from __future__ import annotations

import asyncio
from contextlib import suppress
from importlib.metadata import entry_points
import logging
from pathlib import Path
import signal
from typing import Any

import yaml

from system_sentinel.alerts.handler import AlertHandler
from system_sentinel.chat.base import OutboundMessage
from system_sentinel.chat.registry import ChatRegistry
from system_sentinel.chat.router import ChatRouter
from system_sentinel.core.context import AppContext
from system_sentinel.core.event_bus import InProcessEventBus
from system_sentinel.core.exceptions import ConfigError
from system_sentinel.core.scheduler import Scheduler
from system_sentinel.core.self_update import SelfUpdateError, SelfUpdateMonitor
from system_sentinel.db.audit_repository import SqliteAuditRepository
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.registry import MonitorRegistry

_CONFIG_PATH = Path("/etc/sentinel/config.yaml")
_DB_PATH = Path("/var/lib/sentinel/sentinel.db")

_TOOL_ENTRY_POINT_GROUP = "sentinel.tools"


class DaemonRestartRequested(RuntimeError):
    """Raised when the daemon should exit non-zero so systemd restarts it."""


def _load_config(config_path: Path) -> dict[str, Any]:
    """Load and return the YAML config, raising ConfigError on problems."""
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}. Run `sentinel setup` first.")
    try:
        data = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{config_path} must contain a YAML mapping, got {type(data).__name__}")
    return data


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def _discover_tools(
    tools_config: dict[str, Any],
    app_ctx: AppContext,
    scheduler: Scheduler,
) -> None:
    """Load all tools registered via the ``sentinel.tools`` entry-point group."""
    logger = app_ctx.logger.getChild("tool.registry")
    eps = entry_points(group=_TOOL_ENTRY_POINT_GROUP)
    for ep in eps:
        tool_config: dict[str, Any] = tools_config.get(ep.name, {})
        if not tool_config.get("enabled", True):
            logger.debug("Tool %r is disabled — skipping", ep.name)
            continue
        try:
            cls = ep.load()
            tool = cls(tool_config, app_ctx)
            scheduler.register_tool(tool)
            logger.info("Loaded tool: %s", ep.name)
        except Exception:
            logger.exception("Failed to load tool %r", ep.name)


async def run_daemon(config_path: Path = _CONFIG_PATH, db_path: Path = _DB_PATH) -> None:
    """Wire all components and run the daemon until SIGINT or SIGTERM."""
    _configure_logging()
    logger = logging.getLogger("sentinel")

    config = _load_config(config_path)

    db = DatabaseConnection(db_path)
    await db.connect()

    event_bus = InProcessEventBus()
    audit = SqliteAuditRepository(db)
    app_ctx = AppContext(audit=audit, event_bus=event_bus, logger=logger)

    chat_router = ChatRouter()
    chat_registry = ChatRegistry(config.get("chat_adapters", {}), app_ctx)
    chat_registry.discover()
    for adapter in chat_registry.adapters.values():
        chat_router.register(adapter)

    alert_handler = AlertHandler(chat_router)
    alert_handler.register(event_bus)

    metrics_repo = MetricsRepository(db)
    monitors_config: dict[str, Any] = config.get("monitors", {})
    monitor_registry = MonitorRegistry(monitors_config, app_ctx, metrics_repo)
    monitor_registry.discover()

    scheduler = Scheduler(app_ctx)
    _discover_tools(config.get("tools", {}), app_ctx, scheduler)

    async def _on_self_update_start(remote: str, branch: str) -> None:
        await chat_router.broadcast(
            OutboundMessage(
                title="SystemSentinel update starting",
                text=(
                    f"New version detected on {remote}/{branch}. "
                    "Applying update now; service will restart when complete."
                ),
            )
        )

    self_update_monitor = SelfUpdateMonitor(
        config.get("updates", {}),
        logger,
        on_update_start=_on_self_update_start,
    )

    stop_event = asyncio.Event()
    restart_requested = asyncio.Event()

    def _on_signal() -> None:
        logger.info("Shutdown signal received.")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)

    logger.info("SystemSentinel daemon starting.")

    for adapter in chat_router.adapters:
        await adapter.start()

    await chat_router.broadcast(
        OutboundMessage(
            title="SystemSentinel service started",
            text="SystemSentinel daemon is online and monitoring has started.",
        )
    )

    await monitor_registry.start()
    scheduler.start()
    self_update_task = (
        asyncio.create_task(
            _self_update_loop(
                monitor=self_update_monitor,
                stop_event=stop_event,
                restart_requested=restart_requested,
                logger=logger,
            )
        )
        if self_update_monitor.enabled
        else None
    )

    logger.info("SystemSentinel daemon running. Waiting for shutdown signal.")
    await stop_event.wait()

    logger.info("Shutting down…")
    if self_update_task is not None:
        self_update_task.cancel()
        with suppress(asyncio.CancelledError):
            await self_update_task
    scheduler.stop()
    await monitor_registry.stop()
    for adapter in chat_router.adapters:
        await adapter.stop()
    await db.close()
    logger.info("SystemSentinel daemon stopped.")
    if restart_requested.is_set():
        raise DaemonRestartRequested("Self-update applied. Restarting daemon.")


async def _self_update_loop(
    monitor: SelfUpdateMonitor,
    stop_event: asyncio.Event,
    restart_requested: asyncio.Event,
    logger: logging.Logger,
) -> None:
    while not stop_event.is_set():
        try:
            updated = await monitor.check_and_apply_update()
        except SelfUpdateError as exc:
            logger.error("Self-update check failed: %s", exc)
        else:
            if updated:
                logger.info("Self-update applied. Requesting daemon restart.")
                restart_requested.set()
                stop_event.set()
                return
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=monitor.check_interval_seconds)
        except TimeoutError:
            continue
