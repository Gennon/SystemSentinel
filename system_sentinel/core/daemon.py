from __future__ import annotations

import asyncio
from contextlib import suppress
from importlib.metadata import entry_points
import logging
import os
from pathlib import Path
import signal
from typing import Any, cast

import yaml

from system_sentinel.alerts.handler import AlertHandler
from system_sentinel.chat.access_control import ChatAccessControl
from system_sentinel.chat.base import InboundMessage, OutboundMessage
from system_sentinel.chat.command_dispatcher import ChatCommandDispatcher
from system_sentinel.chat.registry import ChatRegistry
from system_sentinel.chat.router import ChatRouter
from system_sentinel.core.context import AppContext
from system_sentinel.core.event_bus import InProcessEventBus
from system_sentinel.core.exceptions import ConfigError
from system_sentinel.core.scheduler import Scheduler
from system_sentinel.core.self_update import SelfUpdateError, SelfUpdateMonitor
from system_sentinel.core.snapshots import SnapshotManager
from system_sentinel.db.audit_repository import SqliteAuditRepository
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.llm.client import LLMClient
from system_sentinel.llm.registry import LLMRegistry
from system_sentinel.metrics_export.http_server import PrometheusExporterServer
from system_sentinel.monitors.registry import MonitorRegistry

_CONFIG_PATH = Path("/etc/sentinel/config.yaml")
_DB_PATH = Path("/var/lib/sentinel/sentinel.db")
_AUDIT_TEXT_LOG_PATH = Path("/var/log/sentinel/audit.log")

_TOOL_ENTRY_POINT_GROUP = "sentinel.tools"
_ENV_REF_PREFIX = "env:"


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
    resolved = _resolve_env_references(data, path="config")
    if not isinstance(resolved, dict):
        raise ConfigError(
            f"{config_path} must contain a YAML mapping after env resolution, "
            f"got {type(resolved).__name__}"
        )
    return cast("dict[str, Any]", resolved)


def _resolve_env_references(value: Any, *, path: str) -> Any:
    if isinstance(value, dict):
        return {
            key: _resolve_env_references(
                nested_value,
                path=f"{path}.{key}" if isinstance(key, str) else f"{path}[{key!r}]",
            )
            for key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [
            _resolve_env_references(nested_value, path=f"{path}[{index}]")
            for index, nested_value in enumerate(value)
        ]
    if not isinstance(value, str):
        return value

    resolved = value.strip()
    if not resolved.startswith(_ENV_REF_PREFIX):
        return value

    env_var_name = resolved[len(_ENV_REF_PREFIX) :].strip()
    if not env_var_name:
        raise ConfigError(
            f"Invalid environment reference at {path}: expected format "
            f"{_ENV_REF_PREFIX}<VARIABLE_NAME>."
        )

    env_value = os.getenv(env_var_name)
    if env_value is None:
        raise ConfigError(
            f"Config value {path} references environment variable {env_var_name!r}, "
            "but it is not set."
        )
    return env_value


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
) -> dict[str, Any]:
    """Load all tools registered via the ``sentinel.tools`` entry-point group."""
    logger = app_ctx.logger.getChild("tool.registry")
    discovered: dict[str, Any] = {}
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
            discovered[ep.name] = tool
            logger.info("Loaded tool: %s", ep.name)
        except Exception:
            logger.exception("Failed to load tool %r", ep.name)
    return discovered


def _register_tool_event_handlers(event_bus: InProcessEventBus, tools: dict[str, Any]) -> None:
    if not isinstance(tools, dict):
        return
    for tool_name, tool in tools.items():
        event_type = f"tool.{tool_name}.scheduled"

        async def _run_tool(_event_type: str, _payload: Any, *, _tool: Any = tool) -> None:
            await _tool.run()

        event_bus.subscribe(event_type, _run_tool)


async def _run_tools_on_startup(tools: dict[str, Any]) -> None:
    if not isinstance(tools, dict):
        return
    for tool in tools.values():
        if not bool(tool.config.get("run_on_startup", False)):
            continue
        if not tool.is_enabled():
            continue
        await tool.run()


async def run_daemon(config_path: Path = _CONFIG_PATH, db_path: Path = _DB_PATH) -> None:
    """Wire all components and run the daemon until SIGINT or SIGTERM."""
    _configure_logging()
    logger = logging.getLogger("sentinel")

    config = _load_config(config_path)

    db = DatabaseConnection(db_path)
    await db.connect()

    event_bus = InProcessEventBus()
    audit_cfg_raw = config.get("audit", {})
    audit_cfg = audit_cfg_raw if isinstance(audit_cfg_raw, dict) else {}
    audit_text_log_path_raw = audit_cfg.get("text_file_path")
    audit_text_log_path = (
        Path(audit_text_log_path_raw).expanduser()
        if isinstance(audit_text_log_path_raw, str) and audit_text_log_path_raw.strip()
        else _AUDIT_TEXT_LOG_PATH
    )
    text_file_retention_raw = audit_cfg.get("text_file_retention")
    text_file_retention = (
        str(text_file_retention_raw).strip()
        if isinstance(text_file_retention_raw, str) and text_file_retention_raw.strip()
        else None
    )
    audit = SqliteAuditRepository(
        db,
        text_log_path=audit_text_log_path,
        text_log_retention=text_file_retention,
    )
    app_ctx = AppContext(audit=audit, event_bus=event_bus, logger=logger, db=db)

    llm_providers_cfg_raw = config.get("llm_providers", {})
    llm_providers_cfg = llm_providers_cfg_raw if isinstance(llm_providers_cfg_raw, dict) else {}
    llm_cfg_raw = config.get("llm", {})
    llm_cfg = llm_cfg_raw if isinstance(llm_cfg_raw, dict) else {}

    llm_registry = LLMRegistry(llm_providers_cfg, app_ctx)
    llm_registry.discover()
    app_ctx.llm = LLMClient(
        llm_config=llm_cfg,
        providers=llm_registry.providers,
        logger=logger.getChild("llm.client"),
    )

    chat_router = ChatRouter()
    chat_registry = ChatRegistry(config.get("chat_adapters", {}), app_ctx)
    chat_registry.discover()
    for adapter in chat_registry.adapters.values():
        chat_router.register(adapter)

    access_control = ChatAccessControl(
        config=config,
        logger=logger,
        enabled_adapters=set(chat_registry.adapters.keys()),
    )

    async def _handle_inbound_message(
        inbound: InboundMessage, args: list[str]
    ) -> OutboundMessage | None:
        decision = access_control.authorize(inbound, args)
        if not decision.authorized:
            await access_control.audit_rejection(app_ctx.audit, inbound, args, decision.reason)
            if decision.respond_with_message:
                return OutboundMessage(
                    text=access_control.unauthorized_message_for(inbound.adapter),
                    reply_to=inbound,
                )
            return None

        await event_bus.publish(
            "chat.command.authorized",
            {
                "adapter": inbound.adapter,
                "channel_id": inbound.channel_id,
                "user_id": inbound.user_id,
                "username": inbound.username,
                "text": inbound.text,
                "args": args,
                "role": decision.role.value if decision.role is not None else None,
                "received_at": inbound.received_at.isoformat(),
            },
        )
        return await command_dispatcher.handle_message(inbound, args)

    async def _handle_inbound_reaction(reaction: Any) -> OutboundMessage | None:
        return await command_dispatcher.handle_reaction(reaction)

    for adapter in chat_router.adapters:
        adapter.on_message(_handle_inbound_message)
        adapter.on_reaction(_handle_inbound_reaction)

    alert_handler = AlertHandler(chat_router, audit=audit, llm=app_ctx.llm, config=config)
    alert_handler.register(event_bus)

    metrics_repo = MetricsRepository(db)
    monitors_config: dict[str, Any] = config.get("monitors", {})
    monitor_registry = MonitorRegistry(monitors_config, app_ctx, metrics_repo)
    monitor_registry.discover()
    metrics_export_raw = config.get("metrics_export", {})
    metrics_export = metrics_export_raw if isinstance(metrics_export_raw, dict) else {}
    prometheus_raw = metrics_export.get("prometheus", {})
    prometheus_config = prometheus_raw if isinstance(prometheus_raw, dict) else {}
    prometheus_exporter = PrometheusExporterServer(
        config=prometheus_config,
        app_config=config,
        db=db,
        logger=logger.getChild("metrics_export.prometheus"),
    )

    scheduler = Scheduler(app_ctx)
    tools_raw = config.get("tools", {})
    tools_config = tools_raw if isinstance(tools_raw, dict) else {}
    tools = _discover_tools(tools_config, app_ctx, scheduler)
    _register_tool_event_handlers(event_bus, tools)

    command_dispatcher = ChatCommandDispatcher(
        config=config,
        app_ctx=app_ctx,
        scheduler=scheduler,
        tools=tools,
        monitor_registry=monitor_registry,
        db=db,
    )

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

    async def _on_snapshot_warning(message: str) -> None:
        await chat_router.broadcast(
            OutboundMessage(
                title="SystemSentinel snapshot warning",
                text=message,
            )
        )

    self_update_cfg = config.get("updates", {}).get("self_update", {})
    self_update_cfg_dict = self_update_cfg if isinstance(self_update_cfg, dict) else {}
    snapshot_manager = SnapshotManager.from_config(
        self_update_cfg=self_update_cfg_dict,
        audit=audit,
        logger=logger,
    )

    self_update_monitor = SelfUpdateMonitor(
        config.get("updates", {}),
        logger,
        on_update_start=_on_self_update_start,
        snapshot_manager=snapshot_manager,
        on_snapshot_warning=_on_snapshot_warning,
    )

    stop_event = asyncio.Event()
    restart_requested = asyncio.Event()
    reload_tasks: set[asyncio.Task[None]] = set()

    def _on_signal() -> None:
        logger.info("Shutdown signal received.")
        stop_event.set()

    async def _reload_chat_access_config() -> None:
        try:
            reloaded = _load_config(config_path)
        except ConfigError as exc:
            logger.error("Config reload failed: %s", exc)
            await audit.append(
                action_type="config_reload",
                source="daemon",
                description="Config reload failed.",
                outcome="failure",
                details={"error": str(exc)},
            )
            return

        access_control.reload(reloaded, enabled_adapters=set(chat_registry.adapters.keys()))
        await audit.append(
            action_type="config_reload",
            source="daemon",
            description="Chat access control reloaded from config.",
            outcome="success",
        )
        logger.info("Config reloaded for chat access control.")

    def _on_reload_signal() -> None:
        logger.info("Reload signal received.")
        task = asyncio.create_task(_reload_chat_access_config())
        reload_tasks.add(task)
        task.add_done_callback(reload_tasks.discard)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _on_signal)
    if hasattr(signal, "SIGHUP"):
        loop.add_signal_handler(signal.SIGHUP, _on_reload_signal)

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
    await prometheus_exporter.start()
    scheduler.start()
    await _run_tools_on_startup(tools)
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
    for task in list(reload_tasks):
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    scheduler.stop()
    await prometheus_exporter.stop()
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
