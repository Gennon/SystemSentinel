from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any
import uuid

import psutil

from system_sentinel.chat.base import InboundMessage, InboundReaction, OutboundMessage
from system_sentinel.chat.command_handlers import (
    handle_anomalies_command,
    handle_connections_command,
    handle_files_command,
    handle_firewall_command,
    handle_hardening_command,
    handle_help_command,
    handle_snapshots_command,
    handle_storage_command,
)
from system_sentinel.chat.maintenance_utils import (
    parse_older_than_seconds,
    run_cleanup_rules,
)
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.db.login_repository import LoginRepository
from system_sentinel.db.old_files_repository import OldFilesRepository

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.core.scheduler import Scheduler
    from system_sentinel.db.connection import DatabaseConnection
    from system_sentinel.monitors.registry import MonitorRegistry
    from system_sentinel.tools.base import BaseTool, ToolResult

_CONFIRMATION_EMOJI = "✅"
_DEFAULT_PREFIX = "!"
_CONFIRMATION_TTL_SECONDS = 300
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
            "!connections": self._cmd_connections,
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
        )
        return OutboundMessage(
            text=(
                f"Cleanup completed. Deleted {deleted} file(s), reclaimed {reclaimed} bytes, "
                f"failed deletions: {failed}."
            )
        )

    async def _cmd_status(self, message: InboundMessage) -> OutboundMessage:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        uptime_seconds = int(
            (datetime.now(UTC) - datetime.fromtimestamp(psutil.boot_time(), tz=UTC)).total_seconds()
        )
        adapters_count = len(self._config.get("chat_adapters", {}))
        monitors_count = len(self._monitor_registry.monitors)
        tools_count = len(self._tools)
        text = (
            f"CPU {cpu:.1f}% | RAM {ram.percent:.1f}% | Disk {disk.percent:.1f}%\n"
            f"Uptime {uptime_seconds}s\n"
            f"Service health: daemon=running, adapters={adapters_count}, "
            f"monitors={monitors_count}, tools={tools_count}"
        )
        if self._ctx.llm is not None and self._ctx.llm.is_enabled:
            provider = self._ctx.llm.active_provider_name or "unknown"
            text = f"{text}\nLLM: enabled ({provider})"
        else:
            text = f"{text}\nLLM: disabled"
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

    async def _cmd_help(self, message: InboundMessage) -> OutboundMessage:
        return handle_help_command(message=message)

    async def _cmd_connections(self, message: InboundMessage) -> OutboundMessage:
        return await handle_connections_command(
            connection_repo=self._connection_repo,
            message=message,
        )

    async def _active_alert_conditions(self) -> list[str]:
        conditions: list[str] = []
        monitors_cfg = self._config.get("monitors", {})
        now = datetime.now(UTC).isoformat()

        cpu_threshold = float(monitors_cfg.get("cpu", {}).get("alert_threshold_percent", 90))
        ram_threshold = float(monitors_cfg.get("ram", {}).get("alert_threshold_percent", 90))
        disk_threshold = float(monitors_cfg.get("disk", {}).get("alert_threshold_percent", 85))
        network_cfg = monitors_cfg.get("network", {})
        network_sent_threshold_raw = network_cfg.get("alert_threshold_bytes_sent")
        network_recv_threshold_raw = network_cfg.get("alert_threshold_bytes_recv")
        network_sent_threshold = (
            float(network_sent_threshold_raw) if network_sent_threshold_raw is not None else None
        )
        network_recv_threshold = (
            float(network_recv_threshold_raw) if network_recv_threshold_raw is not None else None
        )

        cursor = await self._db.connection.execute(
            """
            SELECT metric_type, data_json
            FROM system_metrics
            WHERE id IN (
                SELECT MAX(id) FROM system_metrics GROUP BY metric_type
            )
            """
        )
        rows = await cursor.fetchall()
        latest_by_type = {str(row[0]): str(row[1]) for row in rows}

        if "cpu" in latest_by_type:
            cpu_data = json.loads(latest_by_type["cpu"])
            cpu_current = float(cpu_data.get("overall_percent", 0.0))
            if cpu_current > cpu_threshold:
                conditions.append(f"CPU high: {cpu_current:.1f}% > {cpu_threshold:.1f}% ({now})")

        if "ram" in latest_by_type:
            ram_data = json.loads(latest_by_type["ram"])
            ram_current = float(ram_data.get("percent", 0.0))
            if ram_current > ram_threshold:
                conditions.append(f"RAM high: {ram_current:.1f}% > {ram_threshold:.1f}% ({now})")

        if "disk" in latest_by_type:
            disk_data = json.loads(latest_by_type["disk"])
            partitions = disk_data.get("partitions", [])
            if isinstance(partitions, list):
                for part in partitions:
                    if not isinstance(part, dict):
                        continue
                    current = float(part.get("percent", 0.0))
                    mount = str(part.get("mountpoint", "unknown"))
                    if current > disk_threshold:
                        conditions.append(
                            f"Disk high on {mount}: {current:.1f}% > {disk_threshold:.1f}% ({now})"
                        )
        if "network" in latest_by_type:
            network_data = json.loads(latest_by_type["network"])
            sent_current = float(network_data.get("bytes_sent", 0.0))
            recv_current = float(network_data.get("bytes_recv", 0.0))
            if network_sent_threshold is not None and sent_current > network_sent_threshold:
                conditions.append(
                    f"Network sent high: {int(sent_current)} B > {int(network_sent_threshold)} B ({now})"
                )
            if network_recv_threshold is not None and recv_current > network_recv_threshold:
                conditions.append(
                    f"Network recv high: {int(recv_current)} B > {int(network_recv_threshold)} B ({now})"
                )
        return conditions

    def _build_storage_report_sync(self, paths: list[str]) -> str:
        lines: list[str] = []
        for raw_path in paths:
            path = str(raw_path).strip()
            if not path:
                continue
            if not os.path.exists(path):
                lines.append(f"{path}: missing")
                continue
            try:
                usage = psutil.disk_usage(path)
            except OSError as exc:
                lines.append(f"{path}: permission denied ({exc})")
                continue
            lines.append(
                f"{path}: used={usage.used} free={usage.free} total={usage.total} ({usage.percent:.1f}%)"
            )
            top_dirs = self._top_subdirs_by_size(path, limit=10)
            for name, size in top_dirs:
                lines.append(f"- {name}: {size} bytes")
        return "\n".join(lines) if lines else "No storage report data available."

    def _top_subdirs_by_size(self, root: str, limit: int = 10) -> list[tuple[str, int]]:
        root_path = Path(root)
        if not root_path.exists() or not root_path.is_dir():
            return []
        sizes: list[tuple[str, int]] = []
        try:
            children = list(root_path.iterdir())
        except OSError:
            return []
        for child in children:
            if not child.is_dir():
                continue
            size = 0
            for dirpath, _dirnames, filenames in os.walk(child, onerror=lambda _err: None):
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    try:
                        size += file_path.stat().st_size
                    except OSError:
                        continue
            sizes.append((str(child), size))
        sizes.sort(key=lambda item: item[1], reverse=True)
        return sizes[:limit]

    def _run_cleanup_rules_sync(self, raw_rules: list[Any]) -> tuple[int, int, int]:
        return run_cleanup_rules(raw_rules)

    def _parse_older_than_seconds(self, raw: object) -> float | None:
        return parse_older_than_seconds(raw)

    def _extract_command(self, adapter_name: str, text: str, args: list[str]) -> str | None:
        prefix = self._command_prefix_for_adapter(adapter_name)
        if args:
            token = args[0].strip()
        else:
            token = text.strip().split(maxsplit=1)[0] if text.strip() else ""
        if not token.startswith(prefix):
            return None
        command = f"!{token[len(prefix) :].lower()}"
        return _COMMAND_ALIASES.get(command, command)

    def _is_in_command_channel(self, message: InboundMessage) -> bool:
        chat_cfg = self._config.get("chat_adapters", {}).get(message.adapter, {})
        if not isinstance(chat_cfg, dict):
            return False
        command_channel_id = chat_cfg.get("command_channel_id", chat_cfg.get("channel_id"))
        if command_channel_id is None:
            return True
        return str(command_channel_id) == message.channel_id

    def _command_prefix_for_adapter(self, adapter_name: str) -> str:
        adapter_cfg = self._config.get("chat_adapters", {}).get(adapter_name, {})
        if isinstance(adapter_cfg, dict):
            raw = adapter_cfg.get("command_prefix")
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
        return _DEFAULT_PREFIX

    async def _record_command(
        self,
        *,
        message: InboundMessage,
        command: str,
        outcome: str,
        result: str,
    ) -> None:
        await self._ctx.audit.append(
            action_type="chat_command",
            source=f"chat:{message.adapter}:{message.user_id}",
            description=f"Processed chat command {command}.",
            outcome=outcome,
            details={
                "adapter": message.adapter,
                "channel_id": message.channel_id,
                "user_id": message.user_id,
                "username": message.username,
                "command": command,
                "result": result,
            },
        )

    async def _record_reaction_command(
        self,
        *,
        reaction: InboundReaction,
        command: str,
        outcome: str,
        result: str,
    ) -> None:
        await self._ctx.audit.append(
            action_type="chat_command",
            source=f"chat:{reaction.adapter}:{reaction.user_id}",
            description=f"Processed confirmed chat command {command}.",
            outcome=outcome,
            details={
                "adapter": reaction.adapter,
                "channel_id": reaction.channel_id,
                "user_id": reaction.user_id,
                "username": reaction.username,
                "command": command,
                "emoji": str(reaction.emoji),
                "result": result,
            },
        )

    async def _llm_context_summary(self) -> str:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        active_alerts = await self._active_alert_conditions()
        recent_alerts = await self._recent_alerts_for_llm(limit=5)
        top_processes = await self._latest_top_processes_for_llm(limit=5)
        lines = [
            f"CPU percent: {cpu:.1f}",
            f"RAM percent: {ram:.1f}",
            f"Disk percent: {disk:.1f}",
        ]
        if active_alerts:
            lines.append("Active alerts:")
            lines.extend(active_alerts[:8])
        else:
            lines.append("Active alerts: none")
        if recent_alerts:
            lines.append("Recent alerts:")
            lines.extend(recent_alerts)
        else:
            lines.append("Recent alerts: none")
        if top_processes:
            lines.append("Top processes by CPU (latest sample):")
            lines.extend(top_processes)
        else:
            lines.append("Top processes by CPU (latest sample): unavailable")
        return "\n".join(lines)

    def _extract_prompt_after_command(self, text: str) -> str | None:
        parts = text.strip().split(maxsplit=1)
        if len(parts) < 2:
            return None
        prompt = parts[1].strip()
        return prompt or None

    async def _recent_alerts_for_llm(self, *, limit: int) -> list[str]:
        cursor = await self._db.connection.execute(
            """
            SELECT timestamp, source, description, details_json
            FROM audit_log
            WHERE action_type = 'alert_fired'
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, limit),),
        )
        rows = await cursor.fetchall()
        alerts: list[str] = []
        for row in rows:
            severity = "unknown"
            details_raw = row[3]
            if isinstance(details_raw, str):
                try:
                    details = json.loads(details_raw)
                except json.JSONDecodeError:
                    details = {}
                if isinstance(details, dict):
                    severity_raw = details.get("severity")
                    if isinstance(severity_raw, str) and severity_raw.strip():
                        severity = severity_raw.strip()
            alerts.append(f"- {row[0]} | {row[1]} | {severity} | {row[2]}")
        return alerts

    async def _latest_top_processes_for_llm(self, *, limit: int) -> list[str]:
        cursor = await self._db.connection.execute(
            """
            SELECT data_json
            FROM system_metrics
            WHERE metric_type = 'cpu'
            ORDER BY id DESC
            LIMIT 1
            """
        )
        row = await cursor.fetchone()
        if row is None:
            return []

        data_raw = row[0]
        if not isinstance(data_raw, str):
            return []
        try:
            data = json.loads(data_raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []
        top_processes = data.get("top_processes")
        if not isinstance(top_processes, list):
            return []

        lines: list[str] = []
        for process in top_processes[: max(1, limit)]:
            if not isinstance(process, dict):
                continue
            name = str(process.get("name", "unknown"))
            pid = process.get("pid")
            cpu_percent = float(process.get("cpu_percent", 0.0))
            ram_bytes = int(process.get("ram_bytes", 0))
            lines.append(f"- {name} (pid={pid}, cpu={cpu_percent:.1f}%, ram={ram_bytes} bytes)")
        return lines
