from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.tools.base import ToolOutcome
from system_sentinel.tools.vulnscan.tool import CommandResult, VulnScanTool

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class _FakeRunner:
    result: CommandResult
    calls: list[list[str]]

    async def run(self, args: list[str]) -> CommandResult:
        self.calls.append(args)
        return self.result


async def _make_tool(
    tmp_path: Path,
    *,
    config: dict[str, Any] | None = None,
    runner: _FakeRunner | None = None,
) -> tuple[VulnScanTool, DatabaseConnection]:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    audit = AsyncMock()
    audit.append = AsyncMock()
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    ctx = AppContext(
        audit=audit,
        event_bus=event_bus,
        logger=logging.getLogger("test"),
        db=db,
    )
    cfg: dict[str, Any] = {"enabled": True}
    if config:
        cfg.update(config)
    tool = VulnScanTool(cfg, ctx, runner=runner)
    return tool, db


def test_default_schedule_is_weekly(tmp_path: Path) -> None:
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    tool = VulnScanTool({"enabled": True}, ctx)
    assert tool.schedule() == "7d 00:00:00"


def test_invalid_schedule_falls_back_to_default() -> None:
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    tool = VulnScanTool({"enabled": True, "schedule": "0 3 * * 1"}, ctx)
    assert tool.schedule() == "7d 00:00:00"


@pytest.mark.asyncio
async def test_run_skips_when_lynis_is_missing(tmp_path: Path) -> None:
    tool, db = await _make_tool(tmp_path)
    tool._lynis_path = None

    result = await tool.run()

    assert result.outcome == ToolOutcome.SKIPPED
    assert "not installed" in result.summary
    await db.close()


@pytest.mark.asyncio
async def test_run_records_scan_and_publishes_summary_event(tmp_path: Path) -> None:
    report_path = tmp_path / "lynis-report.dat"
    report_path.write_text(
        "hardening_index=81\n"
        "warning[]=KRNL-6000|Kernel randomize_va_space is low\n"
        "warning[]=SSH-7408|Password authentication enabled\n"
        "suggestion[]=AUTH-9286|Enable 2FA for SSH access\n"
    )
    runner = _FakeRunner(
        result=CommandResult(returncode=0, stdout="Lynis done\n", stderr=""),
        calls=[],
    )
    tool, db = await _make_tool(
        tmp_path,
        config={"report_path": str(report_path)},
        runner=runner,
    )
    tool._lynis_path = "/usr/bin/lynis"

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert result.details["score"] == 81
    assert result.details["warning_count"] == 2
    assert result.details["suggestion_count"] == 1
    assert tool.ctx.event_bus.publish.await_count == 1
    assert tool.ctx.event_bus.publish.call_args.args[0] == "alert.vulnscan.summary"

    cursor = await db.connection.execute(
        "SELECT score, warning_count, suggestion_count FROM vulnerability_scans"
    )
    row = await cursor.fetchone()
    assert row is not None
    assert int(row[0]) == 81
    assert int(row[1]) == 2
    assert int(row[2]) == 1
    await db.close()


@pytest.mark.asyncio
async def test_run_publishes_score_drop_alert_when_threshold_exceeded(tmp_path: Path) -> None:
    first_report = tmp_path / "lynis-first.dat"
    first_report.write_text("hardening_index=88\nwarning[]=First issue\n")
    second_report = tmp_path / "lynis-second.dat"
    second_report.write_text("hardening_index=70\nwarning[]=Second issue\n")
    runner = _FakeRunner(
        result=CommandResult(returncode=0, stdout="ok", stderr=""),
        calls=[],
    )
    tool, db = await _make_tool(
        tmp_path,
        config={"score_drop_alert_threshold": 10, "report_path": str(first_report)},
        runner=runner,
    )
    tool._lynis_path = "/usr/bin/lynis"
    await tool.run()

    tool.config["report_path"] = str(second_report)
    await tool.run()

    published_event_types = [call.args[0] for call in tool.ctx.event_bus.publish.await_args_list]
    assert "alert.vulnscan.summary" in published_event_types
    assert "alert.vulnscan.score_drop" in published_event_types
    await db.close()
