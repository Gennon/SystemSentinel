from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import psutil

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

    def _get_metrics_repo(self) -> MetricsRepository:
        if self._metrics_repo is not None:
            return self._metrics_repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.metrics_repository import MetricsRepository as _Repo

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
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

        try:
            await self._get_metrics_repo().insert("cpu", data)
        except Exception:
            self.logger.exception("Failed to persist CPU metrics")

    def _sample(self) -> dict[str, Any]:
        overall = psutil.cpu_percent(interval=1)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        return {
            "overall_percent": overall,
            "per_core_percent": per_core,
        }
