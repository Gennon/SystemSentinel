from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.tools.base import ToolOutcome
from system_sentinel.tools.storage.tool import StorageReportTool


def _make_ctx() -> AppContext:
    audit = AsyncMock()
    audit.append = AsyncMock()
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=audit,
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


@pytest.mark.asyncio
async def test_storage_tool_generates_report_and_publishes_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "system_sentinel.tools.storage.tool.build_storage_report",
        lambda _paths, disk_alert_threshold_percent=85.0: (
            f"/: used=1 free=1 total=2 (50.0%) status=OK threshold>{disk_alert_threshold_percent:.1f}%"
        ),
    )
    tool = StorageReportTool({"paths": ["/"], "alert_threshold_percent": 70}, _make_ctx())

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert "Storage report generated" in result.summary
    tool.ctx.event_bus.publish.assert_awaited_once()
    payload = tool.ctx.event_bus.publish.call_args.args[1]
    assert payload["threshold_percent"] == 70.0


@pytest.mark.asyncio
async def test_storage_tool_defaults_to_root_path_when_paths_missing() -> None:
    tool = StorageReportTool({}, _make_ctx())
    assert tool._paths() == ["/"]
