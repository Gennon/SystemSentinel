from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import psutil

from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.metrics_repository import MetricsRepository


class RamMonitor(BaseMonitor):
    """Collects RAM usage metrics (US-005).

    Samples virtual memory statistics and persists them to the
    ``system_metrics`` table via :class:`MetricsRepository`.
    """

    name = "ram"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        metrics_repo: MetricsRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._metrics_repo = metrics_repo

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
        """Sample RAM usage and persist to the database."""
        try:
            data = await asyncio.to_thread(self._sample)
        except Exception:
            self.logger.exception("Failed to collect RAM metrics")
            return

        try:
            repo = await self._get_metrics_repo()
            await repo.insert("ram", data)
        except Exception:
            self.logger.exception("Failed to persist RAM metrics")

    def _sample(self) -> dict[str, Any]:
        vm = psutil.virtual_memory()
        return {
            "total_bytes": vm.total,
            "used_bytes": vm.used,
            "available_bytes": vm.available,
            "percent": vm.percent,
        }
