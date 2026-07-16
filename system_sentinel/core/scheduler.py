from __future__ import annotations

import re
from typing import TYPE_CHECKING

from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-untyped]
from apscheduler.triggers.cron import CronTrigger  # type: ignore[import-untyped]
from apscheduler.triggers.date import DateTrigger  # type: ignore[import-untyped]
from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import-untyped]

from system_sentinel.core.time_config import parse_duration_hhmmss

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.tools.base import BaseTool

_HHMM_RE = re.compile(r"^\d{1,2}:\d{2}$")


class Scheduler:
    """Thin wrapper around APScheduler's ``AsyncIOScheduler``.

    Tools declare their own schedule via :py:meth:`BaseTool.schedule`.  When a
    job fires the Scheduler publishes a ``tool.<name>.scheduled`` event on the
    EventBus rather than calling the tool directly, preserving the event-driven
    architecture.

    Job persistence across restarts can be enabled later by passing a
    ``SQLAlchemyJobStore`` (requires ``sqlalchemy``).  The default in-memory
    store is sufficient for the current release.
    """

    def __init__(self, app_ctx: AppContext) -> None:
        self._ctx = app_ctx
        self._logger = app_ctx.logger.getChild("scheduler")
        self._scheduler: AsyncIOScheduler = AsyncIOScheduler()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the underlying APScheduler."""
        self._scheduler.start()
        self._logger.info("Scheduler started.")

    def stop(self) -> None:
        """Shut down the underlying APScheduler without waiting for running jobs."""
        self._scheduler.shutdown(wait=False)
        self._logger.info("Scheduler stopped.")

    # ------------------------------------------------------------------
    # Job registration
    # ------------------------------------------------------------------

    def register_tool(self, tool: BaseTool) -> None:
        """Register a tool's recurring job if it declares a schedule and is enabled.

        The job publishes ``tool.<name>.scheduled`` rather than calling the tool
        directly, so the tool executor (subscribed to that event) drives the run.
        """
        if not tool.is_enabled():
            self._logger.debug("Tool %r is disabled — skipping schedule registration", tool.name)
            return
        schedule_expr = tool.schedule()
        if schedule_expr is None:
            self._logger.debug("Tool %r has no schedule — skipping", tool.name)
            return

        trigger = self._parse_trigger(schedule_expr)
        self._scheduler.add_job(
            self._publish_scheduled,
            trigger=trigger,
            args=[tool.name],
            id=f"tool.{tool.name}",
            replace_existing=True,
            misfire_grace_time=60,
        )
        self._logger.info("Registered schedule for tool %r: %s", tool.name, schedule_expr)

    async def schedule_once(self, tool_name: str, delay_seconds: float = 0) -> None:
        """Schedule a one-off run of *tool_name*, optionally after a delay.

        Intended for chat-triggered on-demand runs (e.g. ``!update``).
        """
        from datetime import UTC, datetime, timedelta

        run_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
        self._scheduler.add_job(
            self._publish_scheduled,
            trigger=DateTrigger(run_date=run_at),
            args=[tool_name],
            misfire_grace_time=60,
        )
        self._logger.info("Scheduled one-off run of tool %r in %.1fs", tool_name, delay_seconds)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _publish_scheduled(self, tool_name: str) -> None:
        """Publish the ``tool.<name>.scheduled`` event on the EventBus."""
        await self._ctx.event_bus.publish(
            f"tool.{tool_name}.scheduled",
            {"tool_name": tool_name, "source": "scheduler"},
        )

    def _parse_trigger(self, schedule_expr: str) -> CronTrigger | IntervalTrigger:
        """Convert schedule strings into APScheduler triggers.

        Supports:
        - ``HH:MM`` -> daily ``CronTrigger``
        - ``HH:MM:SS`` or ``<days>d HH:MM:SS`` -> ``IntervalTrigger``
        - 5-field cron expression -> ``CronTrigger``
        """
        parsed = parse_duration_hhmmss(schedule_expr)
        if parsed is not None:
            seconds, _is_non_canonical = parsed
            if seconds > 0:
                return IntervalTrigger(seconds=seconds)
        if _HHMM_RE.match(schedule_expr):
            hour_str, minute_str = schedule_expr.split(":")
            return CronTrigger(hour=int(hour_str), minute=int(minute_str))
        return CronTrigger.from_crontab(schedule_expr)
