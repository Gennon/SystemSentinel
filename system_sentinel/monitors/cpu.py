from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import socket
from typing import TYPE_CHECKING, Any

import psutil

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.metrics_repository import MetricsRepository


class CpuMonitor(BaseMonitor):
    """Collects CPU usage metrics (US-005).

    Samples overall and per-core CPU usage percentage and persists them to
    the ``system_metrics`` table via :class:`MetricsRepository`.
    """

    name = "cpu"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        metrics_repo: MetricsRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._metrics_repo = metrics_repo
        self._high_streak = 0
        self._last_alert_at: datetime | None = None

    async def _get_metrics_repo(self) -> MetricsRepository:
        if self._metrics_repo is not None:
            return self._metrics_repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.metrics_repository import MetricsRepository as _Repo

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        repo = _Repo(db)
        self._metrics_repo = repo
        return repo

    async def collect(self) -> None:
        """Sample CPU usage and persist to the database."""
        try:
            data = await asyncio.to_thread(self._sample)
        except Exception:
            self.logger.exception("Failed to collect CPU metrics")
            return

        await self._maybe_emit_alert(data)

        try:
            repo = await self._get_metrics_repo()
            await repo.insert("cpu", data)
        except Exception:
            self.logger.exception("Failed to persist CPU metrics")

    async def _maybe_emit_alert(self, data: dict[str, Any]) -> None:
        threshold = float(self.config.get("alert_threshold_percent", 90))
        consecutive_limit = int(self.config.get("alert_consecutive_intervals", 2))
        cooldown_seconds = parse_duration_from_config(
            self.config,
            key="alert_cooldown",
            default_seconds=30 * 60,
            logger=self.logger,
        )
        current = float(data.get("overall_percent", 0.0))
        now = datetime.now(UTC)

        if current > threshold:
            self._high_streak += 1
        else:
            self._high_streak = 0
            return

        if self._high_streak <= consecutive_limit:
            return

        if (
            self._last_alert_at is not None
            and (now - self._last_alert_at).total_seconds() < cooldown_seconds
        ):
            return

        await self.ctx.event_bus.publish(
            "alert.cpu.threshold_exceeded",
            {
                "event_type": "cpu_threshold_exceeded",
                "current_value": f"{current:.1f}%",
                "threshold": (
                    f">{threshold:.1f}% for more than {consecutive_limit} consecutive intervals"
                ),
                "timestamp": now.isoformat(),
                "hostname": socket.gethostname(),
                "consecutive_intervals": self._high_streak,
            },
        )
        self._last_alert_at = now

    def _sample(self) -> dict[str, Any]:
        overall = psutil.cpu_percent(interval=1)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        top_procs = self._sample_top_processes()
        return {
            "overall_percent": overall,
            "per_core_percent": per_core,
            "top_processes": top_procs,
        }

    def _sample_top_processes(self) -> list[dict[str, Any]]:
        """Return up to 10 processes sorted by CPU usage (descending)."""
        procs: list[dict[str, Any]] = []
        for proc in psutil.process_iter(["name", "pid", "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                ram_bytes = info["memory_info"].rss if info["memory_info"] else 0
                procs.append(
                    {
                        "name": info["name"] or "unknown",
                        "pid": info["pid"],
                        "cpu_percent": info["cpu_percent"] or 0.0,
                        "ram_bytes": ram_bytes,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        procs.sort(key=lambda p: float(p["cpu_percent"]), reverse=True)
        return procs[:10]
