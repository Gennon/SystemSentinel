from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult
from system_sentinel.tools.update.backends import (
    PackageBackend,
    UnsupportedDistroError,
    detect_backend,
)

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext


class SecurityUpdateTool(BaseTool):
    name = "security_update"
    display_name = "Security Updates"
    description = "Applies security-classified package updates on a configurable schedule."

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        backend: PackageBackend | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._backend = backend

    def _get_backend(self) -> PackageBackend:
        return self._backend if self._backend is not None else detect_backend()

    async def run(self) -> ToolResult:
        started_at = datetime.now(UTC)
        dry_run: bool = bool(self.config.get("dry_run", False))
        reboot_policy: str = str(self.config.get("reboot_policy", "notify"))

        try:
            backend = self._get_backend()
        except UnsupportedDistroError as exc:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Unsupported Linux distribution — cannot apply security updates.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
            await self._record(result, stdout=b"", stderr=b"")
            return result

        try:
            stdout, stderr, returncode = await backend.upgrade(dry_run=dry_run)
        except UnsupportedDistroError as exc:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary=str(exc),
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
            await self._record(result, stdout=b"", stderr=b"")
            return result
        except Exception as exc:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Security update failed due to an unexpected error.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
            await self._record(result, stdout=b"", stderr=b"")
            return result

        if dry_run:
            return ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.SKIPPED,
                summary="Dry-run simulated: no changes applied.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                details={"output": stdout.decode(errors="replace")},
            )

        if returncode != 0:
            error_text = stderr.decode(errors="replace").strip()
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Security update command exited with a non-zero status.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=error_text,
                details={"stderr": error_text},
            )
            await self._record(result, stdout=stdout, stderr=stderr)
            await self.ctx.event_bus.publish(
                "tool.update.failed",
                {"error": error_text, "tool": self.name},
            )
            return result

        packages = backend.parse_upgraded_packages(stdout)
        result = ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary=f"Security update completed. {len(packages)} package(s) upgraded.",
            started_at=started_at,
            finished_at=datetime.now(UTC),
            details={"packages_upgraded": packages},
        )
        await self._record(result, stdout=stdout, stderr=stderr)
        await self.ctx.event_bus.publish("tool.update.completed", {"packages": packages})

        if reboot_policy != "never" and await backend.reboot_required():
            await self.ctx.event_bus.publish(
                "tool.update.reboot_required",
                {"message": "A reboot is required to complete the update."},
            )

        return result

    async def dry_run(self) -> ToolResult:
        return await self.run()

    async def _record(self, result: ToolResult, stdout: bytes, stderr: bytes) -> None:
        details: dict[str, Any] = {
            **result.details,
            "stdout": stdout.decode(errors="replace")[:4096],
            "stderr": stderr.decode(errors="replace")[:4096],
        }
        await self.ctx.audit.append(
            action_type="tool_run",
            source="scheduler",
            description=result.summary,
            outcome=result.outcome.value,
            details=details,
        )
