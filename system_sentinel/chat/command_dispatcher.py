from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import fnmatch
import os
from pathlib import Path
import shutil
from typing import TYPE_CHECKING, Any
import uuid

import psutil

from system_sentinel.chat.base import InboundMessage, InboundReaction, OutboundMessage
from system_sentinel.db.connection_repository import ConnectionRepository
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
            "!files": self._cmd_files,
            "!alerts": self._cmd_alerts,
            "!storage": self._cmd_storage,
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
        return OutboundMessage(text=text, reply_to=message)

    async def _cmd_files(self, message: InboundMessage) -> OutboundMessage:
        monitored = (
            self._config.get("monitors", {}).get("old_files", {}).get("watched_directories", [])
        )
        if not isinstance(monitored, list) or not monitored:
            return OutboundMessage(text="No watched directories configured.", reply_to=message)

        lines: list[str] = []
        for raw_dir in monitored:
            watched_dir = str(raw_dir).strip()
            if not watched_dir:
                continue
            rows = await self._old_files_repo.files_for_latest_scan(watched_dir)
            lines.append(f"{watched_dir}: {len(rows)} old file(s)")
            for row in rows[:5]:
                lines.append(
                    f"- {row['file_path']} ({row['age_days']}d, {row['size_bytes']} bytes)"
                )
        if not lines:
            return OutboundMessage(text="No old files found in latest scans.", reply_to=message)
        return OutboundMessage(text="\n".join(lines), reply_to=message)

    async def _cmd_alerts(self, message: InboundMessage) -> OutboundMessage:
        active = await self._active_alert_conditions()
        if not active:
            return OutboundMessage(text="No active alert conditions.", reply_to=message)
        return OutboundMessage(text="\n".join(active), reply_to=message)

    async def _cmd_storage(self, message: InboundMessage) -> OutboundMessage:
        configured_paths = self._config.get("tools", {}).get("storage", {}).get("paths")
        paths = configured_paths if isinstance(configured_paths, list) else []
        if not paths:
            old_files_dirs = (
                self._config.get("monitors", {}).get("old_files", {}).get("watched_directories", [])
            )
            if isinstance(old_files_dirs, list):
                paths = [str(path) for path in old_files_dirs]
        if not paths:
            paths = ["/"]

        report = await asyncio.to_thread(self._build_storage_report_sync, paths)
        return OutboundMessage(text=report, reply_to=message)

    async def _cmd_anomalies(self, message: InboundMessage) -> OutboundMessage:
        since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        cursor = await self._db.connection.execute(
            """
            SELECT timestamp, source, details_json
            FROM audit_log
            WHERE action_type = 'alert_fired'
              AND source = 'alert.login.brute_force_detected'
              AND timestamp >= ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (since,),
        )
        rows = await cursor.fetchall()
        if not rows:
            return OutboundMessage(
                text="No login anomalies in the last 24 hours.", reply_to=message
            )
        lines = ["Recent login anomalies:"]
        for row in rows:
            lines.append(f"- {row[0]} | {row[1]}")
        return OutboundMessage(text="\n".join(lines), reply_to=message)

    async def _cmd_firewall(self, message: InboundMessage) -> OutboundMessage:
        ufw_path = shutil.which("ufw")
        if ufw_path:
            proc = await asyncio.create_subprocess_exec(
                ufw_path,
                "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await proc.communicate()
            text = stdout.decode(errors="replace").strip() or "No firewall status output."
            return OutboundMessage(text=text[:3000], reply_to=message)

        nft_path = shutil.which("nft")
        if nft_path:
            proc = await asyncio.create_subprocess_exec(
                nft_path,
                "list",
                "ruleset",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await proc.communicate()
            text = stdout.decode(errors="replace").strip() or "No firewall rules output."
            return OutboundMessage(text=text[:3000], reply_to=message)

        return OutboundMessage(text="No supported firewall backend detected.", reply_to=message)

    async def _cmd_hardening(self, message: InboundMessage) -> OutboundMessage:
        cursor = await self._db.connection.execute(
            """
            SELECT timestamp, description, outcome
            FROM audit_log
            WHERE action_type = 'tool_run'
              AND description LIKE '%harden%'
            ORDER BY id DESC
            LIMIT 10
            """
        )
        rows = await cursor.fetchall()
        if not rows:
            return OutboundMessage(text="No hardening audit results recorded.", reply_to=message)
        lines = ["Recent hardening audit results:"]
        for row in rows:
            lines.append(f"- {row[0]} | {row[2]} | {row[1]}")
        return OutboundMessage(text="\n".join(lines), reply_to=message)

    async def _cmd_help(self, message: InboundMessage) -> OutboundMessage:
        return OutboundMessage(
            text=(
                "Available commands:\n"
                "!status - CPU, RAM, disk, uptime, and service health\n"
                "!update - run security updates (confirmation required)\n"
                "!cleanup - run file cleanup (confirmation required)\n"
                "!files - list old files from latest scan\n"
                "!alerts - list active alert conditions\n"
                "!storage - generate storage usage report\n"
                "!anomalies - list recent login anomalies\n"
                "!firewall - show firewall status\n"
                "!hardening - show hardening audit results\n"
                "!connections classify - list latest connection intent classifications\n"
                "!help - show this help"
            ),
            reply_to=message,
        )

    async def _cmd_connections(self, message: InboundMessage) -> OutboundMessage:
        parts = message.text.strip().split()
        subcommand = parts[1].lower() if len(parts) > 1 else ""
        if subcommand != "classify":
            return OutboundMessage(
                text="Usage: !connections classify",
                reply_to=message,
            )

        rows = await self._connection_repo.latest_classifications(limit=10)
        if not rows:
            return OutboundMessage(
                text="No classified connection sources recorded yet.",
                reply_to=message,
            )

        lines = ["Latest classified connection sources:"]
        for row in rows:
            confidence = float(row["confidence"])
            reasons = row["reasons"] if isinstance(row["reasons"], list) else []
            reasons_str = ", ".join(str(reason) for reason in reasons[:3]) or "no-reason-data"
            lines.append(
                f"- {row['ip_address']} | {row['category']} | confidence={confidence:.2f} | "
                f"action={row['recommended_action']} | reasons={reasons_str}"
            )
        return OutboundMessage(text="\n".join(lines), reply_to=message)

    async def _active_alert_conditions(self) -> list[str]:
        conditions: list[str] = []
        monitors_cfg = self._config.get("monitors", {})
        now = datetime.now(UTC).isoformat()

        cpu_threshold = float(monitors_cfg.get("cpu", {}).get("alert_threshold_percent", 90))
        ram_threshold = float(monitors_cfg.get("ram", {}).get("alert_threshold_percent", 90))
        disk_threshold = float(monitors_cfg.get("disk", {}).get("alert_threshold_percent", 85))

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

        import json

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
        deleted = 0
        reclaimed = 0
        failed = 0
        now = datetime.now(UTC)
        for raw_rule in raw_rules:
            if not isinstance(raw_rule, dict):
                continue
            path = str(raw_rule.get("path", "")).strip()
            pattern = str(raw_rule.get("pattern", "*")).strip() or "*"
            if not path:
                continue
            older_than = self._parse_older_than_seconds(raw_rule.get("older_than"))
            if older_than is None:
                continue

            root = Path(path)
            if not root.exists() or not root.is_dir():
                continue

            for candidate in root.rglob("*"):
                if not candidate.is_file():
                    continue
                if not fnmatch.fnmatch(candidate.name, pattern):
                    continue
                try:
                    modified = datetime.fromtimestamp(candidate.stat().st_mtime, tz=UTC)
                    if (now - modified).total_seconds() < older_than:
                        continue
                    size = candidate.stat().st_size
                    candidate.unlink()
                    deleted += 1
                    reclaimed += int(size)
                except OSError:
                    failed += 1
        return deleted, reclaimed, failed

    def _parse_older_than_seconds(self, raw: object) -> float | None:
        if not isinstance(raw, str):
            return None
        value = raw.strip()
        if not value:
            return None
        days = 0
        if "d " in value:
            day_part, value = value.split("d ", maxsplit=1)
            if day_part.isdigit():
                days = int(day_part)
        parts = value.split(":")
        if len(parts) != 3:
            return None
        try:
            hours = int(parts[0])
            minutes = int(parts[1])
            seconds = int(parts[2])
        except ValueError:
            return None
        return float(days * 86400 + hours * 3600 + minutes * 60 + seconds)

    def _extract_command(self, adapter_name: str, text: str, args: list[str]) -> str | None:
        prefix = self._command_prefix_for_adapter(adapter_name)
        if args:
            token = args[0].strip()
        else:
            token = text.strip().split(maxsplit=1)[0] if text.strip() else ""
        if not token.startswith(prefix):
            return None
        return f"!{token[len(prefix) :].lower()}"

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
