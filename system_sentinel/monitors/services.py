from __future__ import annotations

import asyncio
from asyncio.subprocess import PIPE
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[list[str]], Awaitable[_CommandResult]]


class ServiceMonitor(BaseMonitor):
    """Monitors critical systemd services and attempts automatic restart (US-012)."""

    name = "services"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        command_runner: CommandRunner | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._command_runner = command_runner or self._run_command
        self._last_check_at: datetime | None = None
        self._attempts_by_service: dict[str, int] = {}
        self._exhausted_services: set[str] = set()

    async def collect(self) -> None:
        services = self._configured_services()
        if not services:
            return

        check_interval_seconds = parse_duration_from_config(
            self.config,
            key="check_interval",
            default_seconds=60,
            logger=self.logger,
        )
        now = datetime.now(UTC)
        if self._last_check_at is not None:
            elapsed = (now - self._last_check_at).total_seconds()
            if elapsed < check_interval_seconds:
                return
        self._last_check_at = now

        max_restart_attempts = self._int_config("max_restart_attempts", default=3, minimum=1)
        journal_lines = self._int_config("journal_lines", default=20, minimum=1)

        for service in services:
            status = await self._service_status(service)
            if status == "active":
                self._attempts_by_service.pop(service, None)
                self._exhausted_services.discard(service)
                continue

            if service in self._exhausted_services:
                continue

            attempt = self._attempts_by_service.get(service, 0) + 1
            self._attempts_by_service[service] = attempt
            journal_excerpt = await self._service_journal_excerpt(service, journal_lines)

            await self.ctx.event_bus.publish(
                "alert.service.failure_detected",
                {
                    "service_name": service,
                    "status": status,
                    "attempt": attempt,
                    "max_attempts": max_restart_attempts,
                    "last_journal_lines": journal_excerpt,
                },
            )

            restart_result = await self._command_runner(
                ["sudo", "/bin/systemctl", "restart", service]
            )
            status_after_restart = await self._service_status(service)
            restart_succeeded = restart_result.returncode == 0 and status_after_restart == "active"

            await self.ctx.audit.append(
                action_type="service_restart_attempt",
                source=f"monitor:{self.name}",
                description=f"Restart attempt {attempt}/{max_restart_attempts} for {service}.",
                outcome="success" if restart_succeeded else "failure",
                details={
                    "service_name": service,
                    "status_before_restart": status,
                    "status_after_restart": status_after_restart,
                    "attempt": attempt,
                    "max_attempts": max_restart_attempts,
                    "restart_return_code": restart_result.returncode,
                    "restart_stdout": self._trim_text(restart_result.stdout),
                    "restart_stderr": self._trim_text(restart_result.stderr),
                },
            )

            await self.ctx.event_bus.publish(
                "alert.service.restart_result",
                {
                    "service_name": service,
                    "attempt": attempt,
                    "max_attempts": max_restart_attempts,
                    "succeeded": restart_succeeded,
                    "status_after_restart": status_after_restart,
                    "error": self._trim_text(restart_result.stderr),
                },
            )

            if restart_succeeded:
                self._attempts_by_service.pop(service, None)
                self._exhausted_services.discard(service)
                continue

            if attempt >= max_restart_attempts:
                self._exhausted_services.add(service)
                await self.ctx.event_bus.publish(
                    "alert.service.restart_exhausted",
                    {
                        "service_name": service,
                        "max_attempts": max_restart_attempts,
                        "status_after_restart": status_after_restart,
                    },
                )

    def _configured_services(self) -> list[str]:
        raw_services = self.config.get("critical_services", self.config.get("services", []))
        if not isinstance(raw_services, list):
            self.logger.warning(
                "Invalid critical_services value %r; expected list[str]. Skipping service checks.",
                raw_services,
            )
            return []
        services = [str(value).strip() for value in raw_services if str(value).strip()]
        return list(dict.fromkeys(services))

    async def _service_status(self, service: str) -> str:
        result = await self._command_runner(["/bin/systemctl", "is-active", service])
        status = result.stdout.strip()
        if status:
            return status
        if result.returncode == 0:
            return "active"
        return "unknown"

    async def _service_journal_excerpt(self, service: str, line_count: int) -> str:
        result = await self._command_runner(
            [
                "/usr/bin/journalctl",
                "-u",
                service,
                "-n",
                str(line_count),
                "--no-pager",
                "--output=short",
            ]
        )
        if result.returncode != 0:
            fallback = result.stderr.strip() or "Unavailable."
            return self._trim_text(fallback)
        lines = [line.rstrip() for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return "No recent journal entries."
        return self._trim_text("\n".join(lines[-line_count:]))

    async def _run_command(self, argv: list[str]) -> _CommandResult:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=PIPE,
            stderr=PIPE,
        )
        stdout_bytes, stderr_bytes = await process.communicate()
        return _CommandResult(
            returncode=process.returncode or 0,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
        )

    def _int_config(self, key: str, *, default: int, minimum: int) -> int:
        raw = self.config.get(key, default)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            self.logger.warning("Invalid %s value %r; using default %d.", key, raw, default)
            return default
        if value < minimum:
            self.logger.warning("%s=%d is below minimum %d; using minimum.", key, value, minimum)
            return minimum
        return value

    def _trim_text(self, text: str, *, limit: int = 1200) -> str:
        if len(text) <= limit:
            return text
        return f"{text[:limit]}…"
