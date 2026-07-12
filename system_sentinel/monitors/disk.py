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


class DiskMonitor(BaseMonitor):
    """Collects disk usage metrics per mounted volume (US-005).

    For each mounted filesystem, records total/used/free bytes and usage
    percentage, then persists the sample to ``system_metrics``.
    """

    name = "disk"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        metrics_repo: MetricsRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._metrics_repo = metrics_repo
        self._last_alert_at_by_mountpoint: dict[str, datetime] = {}

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
        """Sample disk usage for all mounted volumes and persist to the database."""
        try:
            data = await asyncio.to_thread(self._sample)
        except Exception:
            self.logger.exception("Failed to collect disk metrics")
            return

        await self._maybe_emit_alerts(data)

        try:
            repo = await self._get_metrics_repo()
            await repo.insert("disk", data)
        except Exception:
            self.logger.exception("Failed to persist disk metrics")

    async def _maybe_emit_alerts(self, data: dict[str, Any]) -> None:
        threshold = float(self.config.get("alert_threshold_percent", 85))
        cooldown_seconds = parse_duration_from_config(
            self.config,
            key="alert_cooldown",
            default_seconds=30 * 60,
            logger=self.logger,
        )
        partitions = data.get("partitions", [])
        if not isinstance(partitions, list):
            return
        now = datetime.now(UTC)
        hostname = socket.gethostname()

        for part in partitions:
            if not isinstance(part, dict):
                continue
            mountpoint = str(part.get("mountpoint", "unknown"))
            current = float(part.get("percent", 0.0))
            if current <= threshold:
                continue
            last_alert = self._last_alert_at_by_mountpoint.get(mountpoint)
            if last_alert is not None and (now - last_alert).total_seconds() < cooldown_seconds:
                continue

            await self.ctx.event_bus.publish(
                "alert.disk.threshold_exceeded",
                {
                    "event_type": "disk_threshold_exceeded",
                    "current_value": f"{current:.1f}%",
                    "threshold": f">{threshold:.1f}%",
                    "timestamp": now.isoformat(),
                    "hostname": hostname,
                    "mountpoint": mountpoint,
                    "device": str(part.get("device", "unknown")),
                },
            )
            self._last_alert_at_by_mountpoint[mountpoint] = now

    def _sample(self) -> dict[str, Any]:
        partitions: list[dict[str, Any]] = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except PermissionError:
                continue
            partitions.append(
                {
                    "mountpoint": part.mountpoint,
                    "device": part.device,
                    "fstype": part.fstype,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent": usage.percent,
                }
            )
        return {"partitions": partitions}
