from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.core.scheduler import Scheduler


def _make_ctx() -> AppContext:
    return AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )


@pytest.fixture
def ctx() -> AppContext:
    return _make_ctx()


@pytest.fixture
def scheduler(ctx: AppContext) -> Scheduler:
    s = Scheduler(ctx)
    s._scheduler = MagicMock()  # replace real APScheduler with mock
    return s


def _enabled_tool(name: str, schedule_expr: str | None) -> MagicMock:
    tool = MagicMock()
    tool.name = name
    tool.is_enabled.return_value = True
    tool.schedule.return_value = schedule_expr
    return tool


def _disabled_tool(name: str) -> MagicMock:
    tool = MagicMock()
    tool.name = name
    tool.is_enabled.return_value = False
    return tool


class TestRegisterTool:
    def test_hhmm_schedule_registers_job(self, scheduler: Scheduler) -> None:
        tool = _enabled_tool("update", "02:00")
        scheduler.register_tool(tool)
        scheduler._scheduler.add_job.assert_called_once()
        kwargs = scheduler._scheduler.add_job.call_args.kwargs
        assert kwargs["id"] == "tool.update"
        assert kwargs["replace_existing"] is True

    def test_cron_schedule_registers_job(self, scheduler: Scheduler) -> None:
        tool = _enabled_tool("harden", "0 3 * * 0")
        scheduler.register_tool(tool)
        scheduler._scheduler.add_job.assert_called_once()

    def test_disabled_tool_skipped(self, scheduler: Scheduler) -> None:
        tool = _disabled_tool("update")
        scheduler.register_tool(tool)
        scheduler._scheduler.add_job.assert_not_called()

    def test_no_schedule_skipped(self, scheduler: Scheduler) -> None:
        tool = _enabled_tool("packages", None)
        scheduler.register_tool(tool)
        scheduler._scheduler.add_job.assert_not_called()

    def test_multiple_tools_each_get_unique_job_id(self, scheduler: Scheduler) -> None:
        scheduler.register_tool(_enabled_tool("update", "02:00"))
        scheduler.register_tool(_enabled_tool("harden", "0 3 * * 0"))
        assert scheduler._scheduler.add_job.call_count == 2
        ids = [c.kwargs["id"] for c in scheduler._scheduler.add_job.call_args_list]
        assert ids == ["tool.update", "tool.harden"]


class TestParseTriger:
    def test_hhmm_midnight(self, ctx: AppContext) -> None:
        from apscheduler.triggers.cron import CronTrigger

        s = Scheduler(ctx)
        trigger = s._parse_trigger("00:00")
        assert isinstance(trigger, CronTrigger)

    def test_hhmm_two_am(self, ctx: AppContext) -> None:
        from apscheduler.triggers.cron import CronTrigger

        s = Scheduler(ctx)
        trigger = s._parse_trigger("02:00")
        assert isinstance(trigger, CronTrigger)

    def test_cron_expression(self, ctx: AppContext) -> None:
        from apscheduler.triggers.cron import CronTrigger

        s = Scheduler(ctx)
        trigger = s._parse_trigger("0 3 * * 0")
        assert isinstance(trigger, CronTrigger)


class TestScheduleOnce:
    @pytest.mark.asyncio
    async def test_adds_date_trigger_job(self, scheduler: Scheduler) -> None:
        await scheduler.schedule_once("update", delay_seconds=0)
        scheduler._scheduler.add_job.assert_called_once()

    @pytest.mark.asyncio
    async def test_adds_job_with_delay(self, scheduler: Scheduler) -> None:
        await scheduler.schedule_once("update", delay_seconds=30)
        scheduler._scheduler.add_job.assert_called_once()
        args = scheduler._scheduler.add_job.call_args.args
        assert args[0] == scheduler._publish_scheduled

    @pytest.mark.asyncio
    async def test_passes_tool_name_as_arg(self, scheduler: Scheduler) -> None:
        await scheduler.schedule_once("harden")
        kwargs = scheduler._scheduler.add_job.call_args.kwargs
        assert kwargs["args"] == ["harden"]


class TestPublishScheduled:
    @pytest.mark.asyncio
    async def test_publishes_correct_event_type(self, ctx: AppContext) -> None:
        scheduler = Scheduler(ctx)
        await scheduler._publish_scheduled("update")
        ctx.event_bus.publish.assert_called_once_with(
            "tool.update.scheduled",
            {"tool_name": "update", "source": "scheduler"},
        )

    @pytest.mark.asyncio
    async def test_publishes_event_for_any_tool(self, ctx: AppContext) -> None:
        scheduler = Scheduler(ctx)
        await scheduler._publish_scheduled("harden")
        ctx.event_bus.publish.assert_called_once()
        event_type = ctx.event_bus.publish.call_args.args[0]
        assert event_type == "tool.harden.scheduled"


class TestStartStop:
    def test_start_calls_scheduler_start(self, scheduler: Scheduler) -> None:
        scheduler.start()
        scheduler._scheduler.start.assert_called_once()

    def test_stop_calls_scheduler_shutdown(self, scheduler: Scheduler) -> None:
        scheduler.stop()
        scheduler._scheduler.shutdown.assert_called_once()
