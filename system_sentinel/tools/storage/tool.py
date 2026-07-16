from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.maintenance_utils import build_storage_report
from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext


class StorageReportTool(BaseTool):
    name = "storage"
    display_name = "Storage Report"
    description = "Generates storage usage reports with top directory consumers."

    def __init__(self, config: dict[str, Any], app_ctx: AppContext) -> None:
        super().__init__(config, app_ctx)

    async def run(self) -> ToolResult:
        started_at = datetime.now(UTC)
        paths = self._paths()
        disk_threshold_percent = float(self.config.get("alert_threshold_percent", 85))
        source = "scheduler"

        try:
            report = await asyncio.to_thread(
                build_storage_report,
                paths,
                disk_alert_threshold_percent=disk_threshold_percent,
            )
        except Exception as exc:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Storage report generation failed due to an unexpected error.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=str(exc),
                details={"paths": paths, "threshold_percent": disk_threshold_percent},
            )
            await self._record(result)
            return result

        flagged_paths = report.count("status=ALERT")
        summary = (
            f"Storage report generated for {len(paths)} path(s); "
            f"{flagged_paths} path(s) above threshold."
        )
        result = ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary=summary,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            details={
                "paths": paths,
                "threshold_percent": disk_threshold_percent,
                "flagged_paths": flagged_paths,
            },
        )
        await self._record(result)
        await self.ctx.event_bus.publish(
            "alert.storage.report_generated",
            {
                "event_type": "storage_report_generated",
                "generated_at": datetime.now(UTC).isoformat(),
                "paths": paths,
                "threshold_percent": disk_threshold_percent,
                "flagged_paths": flagged_paths,
                "source": source,
                "report": report,
            },
        )
        return result

    def _paths(self) -> list[str]:
        raw_paths = self.config.get("paths", [])
        if not isinstance(raw_paths, list):
            return ["/"]
        paths = [str(path).strip() for path in raw_paths if str(path).strip()]
        return paths or ["/"]

    async def _record(self, result: ToolResult) -> None:
        await self.ctx.audit.append(
            action_type="tool_run",
            source="scheduler",
            description=result.summary,
            outcome=result.outcome.value,
            details=result.details,
        )
