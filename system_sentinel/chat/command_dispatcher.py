from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import re
from typing import TYPE_CHECKING, Any
import uuid

import psutil

from system_sentinel.charts.registry import ChartRendererRegistry
from system_sentinel.charts.renderers.text import TextChartRenderer
from system_sentinel.chat.base import InboundMessage, InboundReaction, OutboundMessage
from system_sentinel.chat.command_graph import handle_graph_command
from system_sentinel.chat.command_handlers import (
    handle_anomalies_command,
    handle_audit_command,
    handle_connections_command,
    handle_files_command,
    handle_firewall_command,
    handle_hardening_command,
    handle_help_command,
    handle_snapshots_command,
    handle_storage_command,
)
from system_sentinel.chat.command_insights import (
    build_llm_context_summary,
    build_status_text,
    extract_prompt_after_command,
)
from system_sentinel.chat.command_metrics import get_active_alert_conditions
from system_sentinel.chat.command_support import (
    command_prefix_for_adapter,
    extract_command,
    is_in_command_channel,
    record_command,
    record_reaction_command,
)
from system_sentinel.chat.maintenance_utils import (
    build_storage_report,
    parse_older_than_seconds,
    run_cleanup_rules,
)
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.core.time_config import parse_duration_hhmmss
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.db.login_repository import LoginRepository
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.db.old_files_repository import OldFilesRepository

if TYPE_CHECKING:
    from system_sentinel.charts.base import BaseChartRenderer
    from system_sentinel.core.context import AppContext
    from system_sentinel.core.scheduler import Scheduler
    from system_sentinel.db.connection import DatabaseConnection
    from system_sentinel.monitors.registry import MonitorRegistry
    from system_sentinel.tools.base import BaseTool, ToolResult

_CONFIRMATION_EMOJI = "✅"
_DEFAULT_PREFIX = "!"
_CONFIRMATION_TTL_SECONDS = 300
_MUTE_SHORT_DURATION_RE = re.compile(r"^(?P<value>\d+)\s*(?P<unit>[smhdSMHD])$")
_COMMAND_ALIASES = {
    "!snaphsots": "!snapshots",
}
CommandCallable = Callable[[InboundMessage], Awaitable[OutboundMessage]]


@dataclass(frozen=True)
class PendingAction:
    command: str
    requested_at: datetime
    expires_at: datetime
    request_id: str


class ChatCommandDispatcher:
    """Parses chat commands and executes supported command handlers."""

    def __init__(
        self,
        *,
        config: dict[str, Any],
        app_ctx: AppContext,
        scheduler: Scheduler,
        tools: dict[str, BaseTool],
        monitor_registry: MonitorRegistry,
        db: DatabaseConnection,
    ) -> None:
        self._config = config
        self._ctx = app_ctx
        self._scheduler = scheduler
        self._tools = tools
        self._monitor_registry = monitor_registry
        self._db = db
        self._old_files_repo = OldFilesRepository(db)
        self._connection_repo = ConnectionRepository(db)
        self._login_repo = LoginRepository(db)
        self._metrics_repo = MetricsRepository(db)
        self._chart_renderer = self._load_chart_renderer()
        self._pending_actions: dict[tuple[str, str, str], PendingAction] = {}

    async def handle_message(
        self, message: InboundMessage, args: list[str]
    ) -> OutboundMessage | None:
        command = self._extract_command(message.adapter, message.text, args)
        if command is None:
            return None
        if not self._is_in_command_channel(message):
            return None

        handlers: dict[str, CommandCallable] = {
            "!status": self._cmd_status,
            "!ask": self._cmd_ask,
            "!files": self._cmd_files,
            "!alerts": self._cmd_alerts,
            "!storage": self._cmd_storage,
            "!snapshots": self._cmd_snapshots,
            "!anomalies": self._cmd_anomalies,
            "!firewall": self._cmd_firewall,
            "!hardening": self._cmd_hardening,
            "!audit": self._cmd_audit,
            "!graph": self._cmd_graph,
            "!connections": self._cmd_connections,
            "!mute": self._cmd_mute,
            "!unmute": self._cmd_unmute,
            "!help": self._cmd_help,
        }
        action_commands = {"!update", "!cleanup"}

        if command in action_commands:
            await self._record_command(
                message=message,
                command=command,
                outcome="success",
                result="confirmation_requested",
            )
            return self._request_confirmation(message, command)

        handler = handlers.get(command)
        if handler is None:
            await self._record_command(
                message=message,
                command=command,
                outcome="failure",
                result="unsupported_command",
            )
            return OutboundMessage(
                text=f"Unknown command: {command}. Use !help to see supported commands.",
                reply_to=message,
            )

        response = await handler(message)
        await self._record_command(
            message=message,
            command=command,
            outcome="success",
            result="executed",
        )
        return response

    async def handle_reaction(self, reaction: InboundReaction) -> OutboundMessage | None:
        if str(reaction.emoji) != _CONFIRMATION_EMOJI:
            return None
        key = (reaction.adapter, reaction.channel_id, reaction.user_id)
        pending = self._pending_actions.get(key)
        if pending is None:
            return None
        now = datetime.now(UTC)
        if now > pending.expires_at:
            del self._pending_actions[key]
            return OutboundMessage(text="Confirmation expired. Run the command again.")

        del self._pending_actions[key]
        if pending.command == "!update":
            return await self._execute_tool_action("security_update", reaction, pending.command)
        if pending.command == "!cleanup":
            return await self._execute_cleanup_action(reaction, pending.command)
        return None

    def _request_confirmation(self, message: InboundMessage, command: str) -> OutboundMessage:
        now = datetime.now(UTC)
        request_id = uuid.uuid4().hex[:8]
        self._pending_actions[(message.adapter, message.channel_id, message.user_id)] = (
            PendingAction(
                command=command,
                requested_at=now,
                expires_at=now + timedelta(seconds=_CONFIRMATION_TTL_SECONDS),
                request_id=request_id,
            )
        )
        return OutboundMessage(
            text=(
                f"Confirm {command} by reacting with {_CONFIRMATION_EMOJI} within "
                f"{_CONFIRMATION_TTL_SECONDS // 60} minutes."
            ),
            reply_to=message,
        )

    async def _execute_tool_action(
        self,
        tool_name: str,
        reaction: InboundReaction,
        command: str,
    ) -> OutboundMessage:
        tool = self._tools.get(tool_name)
        if tool is None:
            await self._record_reaction_command(
                reaction=reaction,
                command=command,
                outcome="failure",
                result="tool_not_configured",
            )
            return OutboundMessage(text=f"{command} is not configured.")

        result: ToolResult = await tool.run()
        await self._record_reaction_command(
            reaction=reaction,
            command=command,
            outcome=result.outcome.value,
            result="executed",
        )
        return OutboundMessage(text=result.summary)

    async def _execute_cleanup_action(
        self,
        reaction: InboundReaction,
        command: str,
    ) -> OutboundMessage:
        cleanup_cfg = self._config.get("tools", {}).get("cleanup", {})
        rules = cleanup_cfg.get("rules", [])
        if not isinstance(rules, list) or not rules:
            await self._record_reaction_command(
                reaction=reaction,
                command=command,
                outcome="failure",
                result="cleanup_rules_missing",
            )
            return OutboundMessage(text="No cleanup rules configured.")

        deleted, reclaimed, failed = await asyncio.to_thread(self._run_cleanup_rules_sync, rules)
        await self._record_reaction_command(
            reaction=reaction,
            command=command,
            outcome="success" if not failed else "failure",
            result="executed",
            extra_details={
                "cleanup": {
                    "deleted_files": deleted,
                    "reclaimed_bytes": reclaimed,
                    "failed_deletions": failed,
                }
            },
        )
        return OutboundMessage(
            text=(
                f"Cleanup completed. Deleted {deleted} file(s), reclaimed {reclaimed} bytes, "
                f"failed deletions: {failed}."
            )
        )

    async def _cmd_status(self, message: InboundMessage) -> OutboundMessage:
        text = build_status_text(
            config=self._config,
            monitor_count=len(self._monitor_registry.monitors),
            tool_count=len(self._tools),
            llm_client=self._ctx.llm,
            psutil_module=psutil,
        )
        return OutboundMessage(text=text, reply_to=message)

    async def _cmd_ask(self, message: InboundMessage) -> OutboundMessage:
        llm_client = self._ctx.llm
        if llm_client is None:
            return OutboundMessage(
                text="LLM assistant is not configured. Configure `llm` and `llm_providers` in config.yaml.",
                reply_to=message,
            )

        question = self._extract_prompt_after_command(message.text)
        if question is None:
            return OutboundMessage(
                text="Usage: !ask <question>",
                reply_to=message,
            )

        context = await self._llm_context_summary()
        prompt = f"User question:\n{question}\n\nCurrent system context:\n{context}"
        system_prompt = (
            "You are SystemSentinel assistant. Explain likely causes and practical next steps. "
            "If uncertain, say so clearly."
        )
        try:
            result = await llm_client.complete(
                prompt=prompt,
                system_prompt=system_prompt,
                timeout_seconds=30.0,
            )
        except LLMUnavailableError as exc:
            return OutboundMessage(
                text=f"LLM assistant unavailable: {exc}",
                reply_to=message,
            )

        await self._ctx.audit.append(
            action_type="llm_query",
            source=f"chat:{message.adapter}:{message.user_id}",
            description="Processed chat LLM query.",
            outcome="success",
            details={
                "adapter": message.adapter,
                "channel_id": message.channel_id,
                "user_id": message.user_id,
                "username": message.username,
                "question": question,
                "provider": result.provider,
                "model": result.model_used,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "context": context,
                "response": result.text,
            },
        )

        return OutboundMessage(
            text=f"[{result.provider}:{result.model_used}]\n{result.text[:2800]}",
            reply_to=message,
        )

    async def _cmd_files(self, message: InboundMessage) -> OutboundMessage:
        return await handle_files_command(
            config=self._config,
            old_files_repo=self._old_files_repo,
            message=message,
        )

    async def _cmd_alerts(self, message: InboundMessage) -> OutboundMessage:
        active = await self._active_alert_conditions()
        if not active:
            return OutboundMessage(text="No active alert conditions.", reply_to=message)
        return OutboundMessage(text="\n".join(active), reply_to=message)

    async def _cmd_storage(self, message: InboundMessage) -> OutboundMessage:
        return await handle_storage_command(
            config=self._config,
            message=message,
            build_storage_report_sync=self._build_storage_report_sync,
        )

    async def _cmd_anomalies(self, message: InboundMessage) -> OutboundMessage:
        return await handle_anomalies_command(login_repo=self._login_repo, message=message)

    async def _cmd_snapshots(self, message: InboundMessage) -> OutboundMessage:
        return await handle_snapshots_command(db=self._db, message=message)

    async def _cmd_firewall(self, message: InboundMessage) -> OutboundMessage:
        return await handle_firewall_command(
            tools=self._tools,
            logger=self._ctx.logger.getChild("chat.command_dispatcher"),
            message=message,
        )

    async def _cmd_hardening(self, message: InboundMessage) -> OutboundMessage:
        return await handle_hardening_command(db=self._db, message=message)

    async def _cmd_audit(self, message: InboundMessage) -> OutboundMessage:
        return await handle_audit_command(db=self._db, message=message)

    async def _cmd_graph(self, message: InboundMessage) -> OutboundMessage:
        return await handle_graph_command(
            message=message,
            metrics_repo=self._metrics_repo,
            chart_renderer=self._chart_renderer,
        )

    async def _cmd_help(self, message: InboundMessage) -> OutboundMessage:
        return handle_help_command(message=message)

    async def _cmd_connections(self, message: InboundMessage) -> OutboundMessage:
        return await handle_connections_command(
            connection_repo=self._connection_repo,
            message=message,
        )

    async def _cmd_mute(self, message: InboundMessage) -> OutboundMessage:
        duration_seconds = self._extract_mute_duration_seconds(message.text)
        if duration_seconds is None:
            return OutboundMessage(
                text="Usage: !mute <duration> (examples: !mute 2h, !mute 30m, !mute 01:30:00)",
                reply_to=message,
            )
        mute_until = datetime.now(UTC) + timedelta(seconds=duration_seconds)
        await self._ctx.event_bus.publish(
            "chat.alerts.mute",
            {
                "mute_until": mute_until.isoformat(),
                "duration_seconds": duration_seconds,
                "adapter": message.adapter,
                "channel_id": message.channel_id,
                "user_id": message.user_id,
            },
        )
        return OutboundMessage(
            text=(f"Muted non-critical alerts until {mute_until.strftime('%Y-%m-%d %H:%M:%SZ')}."),
            reply_to=message,
        )

    async def _cmd_unmute(self, message: InboundMessage) -> OutboundMessage:
        await self._ctx.event_bus.publish(
            "chat.alerts.unmute",
            {
                "adapter": message.adapter,
                "channel_id": message.channel_id,
                "user_id": message.user_id,
            },
        )
        return OutboundMessage(text="Non-critical alerts unmuted.", reply_to=message)

    async def _active_alert_conditions(self) -> list[str]:
        return await get_active_alert_conditions(
            config=self._config,
            db=self._db,
            now_iso=datetime.now(UTC).isoformat(),
        )

    def _build_storage_report_sync(self, paths: list[str], disk_threshold_percent: float) -> str:
        return build_storage_report(paths, disk_alert_threshold_percent=disk_threshold_percent)

    def _run_cleanup_rules_sync(self, raw_rules: list[Any]) -> tuple[int, int, int]:
        return run_cleanup_rules(raw_rules)

    def _parse_older_than_seconds(self, raw: object) -> float | None:
        return parse_older_than_seconds(raw)

    def _extract_command(self, adapter_name: str, text: str, args: list[str]) -> str | None:
        return extract_command(
            config=self._config,
            adapter_name=adapter_name,
            text=text,
            args=args,
            default_prefix=_DEFAULT_PREFIX,
            aliases=_COMMAND_ALIASES,
        )

    def _is_in_command_channel(self, message: InboundMessage) -> bool:
        return is_in_command_channel(config=self._config, message=message)

    def _command_prefix_for_adapter(self, adapter_name: str) -> str:
        return command_prefix_for_adapter(
            config=self._config,
            adapter_name=adapter_name,
            default_prefix=_DEFAULT_PREFIX,
        )

    async def _record_command(
        self,
        *,
        message: InboundMessage,
        command: str,
        outcome: str,
        result: str,
    ) -> None:
        await record_command(
            audit=self._ctx.audit,
            message=message,
            command=command,
            outcome=outcome,
            result=result,
        )

    async def _record_reaction_command(
        self,
        *,
        reaction: InboundReaction,
        command: str,
        outcome: str,
        result: str,
        extra_details: dict[str, Any] | None = None,
    ) -> None:
        await record_reaction_command(
            audit=self._ctx.audit,
            reaction=reaction,
            command=command,
            outcome=outcome,
            result=result,
            extra_details=extra_details,
        )

    async def _llm_context_summary(self) -> str:
        active_alerts = await self._active_alert_conditions()
        return await build_llm_context_summary(
            db=self._db,
            psutil_module=psutil,
            active_alerts=active_alerts,
        )

    def _extract_prompt_after_command(self, text: str) -> str | None:
        return extract_prompt_after_command(text)

    def _extract_mute_duration_seconds(self, text: str) -> float | None:
        parts = text.strip().split(maxsplit=1)
        if len(parts) < 2:
            return None
        raw_duration = parts[1].strip()
        if not raw_duration:
            return None
        parsed_hhmmss = parse_duration_hhmmss(raw_duration)
        if parsed_hhmmss is not None:
            seconds, _is_non_canonical = parsed_hhmmss
            return seconds if seconds > 0 else None
        short = _MUTE_SHORT_DURATION_RE.fullmatch(raw_duration)
        if short is None:
            return None
        value = int(short.group("value"))
        if value <= 0:
            return None
        unit = short.group("unit").lower()
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        multiplier = multipliers.get(unit)
        if multiplier is None:
            return None
        return float(value * multiplier)

    def _load_chart_renderer(self) -> BaseChartRenderer:
        charts_cfg = self._config.get("charts", {})
        renderer_name_raw = charts_cfg.get("renderer") if isinstance(charts_cfg, dict) else None
        renderer_name = (
            str(renderer_name_raw).strip().lower()
            if renderer_name_raw is not None and str(renderer_name_raw).strip()
            else "text"
        )

        registry = ChartRendererRegistry(self._ctx.logger.getChild("charts.registry"))
        registry.discover()
        renderer = registry.get(renderer_name)
        if renderer is not None:
            return renderer

        self._ctx.logger.warning(
            "Unknown chart renderer %r configured. Falling back to 'text'.",
            renderer_name,
        )
        return TextChartRenderer()
