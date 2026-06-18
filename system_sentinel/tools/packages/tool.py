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


class RequiredPackagesTool(BaseTool):
    name = "required_packages"
    display_name = "Required Packages"
    description = "Ensures all configured required packages are installed, auto-reinstalling any that are missing."

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
        required: list[str] = list(self.config.get("required", []))

        try:
            backend = self._get_backend()
        except UnsupportedDistroError as exc:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Unsupported Linux distribution — cannot manage required packages.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
            await self._record(result)
            return result

        missing: list[str] = []
        for pkg in required:
            if not await backend.is_installed(pkg):
                missing.append(pkg)

        if not missing:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.SUCCESS,
                summary=f"All {len(required)} required package(s) are present.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                details={"missing": [], "installed": [], "failed": []},
            )
            await self._record(result)
            return result

        for pkg in missing:
            await self.ctx.event_bus.publish(
                "tool.packages.missing_detected",
                {"package": pkg},
            )

        installed: list[str] = []
        failed: list[str] = []
        first_error: str | None = None

        for pkg in missing:
            try:
                _stdout, stderr, returncode = await backend.install(pkg)
            except Exception as exc:
                failed.append(pkg)
                if first_error is None:
                    first_error = str(exc)
                await self.ctx.event_bus.publish(
                    "tool.packages.install_failed",
                    {"package": pkg, "error": str(exc)},
                )
                continue

            if returncode != 0:
                error_text = stderr.decode(errors="replace").strip()
                failed.append(pkg)
                if first_error is None:
                    first_error = error_text
                await self.ctx.event_bus.publish(
                    "tool.packages.install_failed",
                    {"package": pkg, "error": error_text},
                )
            else:
                installed.append(pkg)
                await self.ctx.event_bus.publish(
                    "tool.packages.installed",
                    {"package": pkg},
                )

        if failed:
            outcome = ToolOutcome.FAILURE
            summary = (
                f"{len(installed)} package(s) reinstalled, "
                f"{len(failed)} failed: {', '.join(failed)}."
            )
        else:
            outcome = ToolOutcome.SUCCESS
            summary = f"{len(installed)} missing package(s) reinstalled: {', '.join(installed)}."

        result = ToolResult(
            tool_name=self.name,
            outcome=outcome,
            summary=summary,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            error=first_error,
            details={"missing": missing, "installed": installed, "failed": failed},
        )
        await self._record(result)
        return result

    async def _record(self, result: ToolResult) -> None:
        await self.ctx.audit.append(
            action_type="tool_run",
            source="scheduler",
            description=result.summary,
            outcome=result.outcome.value,
            details=result.details,
        )
