from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import psutil

from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.metrics_repository import MetricsRepository


class NetworkMonitor(BaseMonitor):
    """Collects network I/O delta metrics (US-005).

    Records bytes sent and received *since the previous collection interval*
    by comparing successive :func:`psutil.net_io_counters` snapshots.
    On the first call the baseline is established and no data is persisted.
    """

    name = "network"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        metrics_repo: MetricsRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._metrics_repo = metrics_repo
        self._prev_bytes_sent: int | None = None
        self._prev_bytes_recv: int | None = None

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
        """Sample network I/O counters and persist the delta since last call."""
        try:
            counters = await asyncio.to_thread(psutil.net_io_counters)
        except Exception:
            self.logger.exception("Failed to collect network metrics")
            return

        if counters is None:
            self.logger.warning("psutil.net_io_counters returned None — no network interfaces?")
            return

        bytes_sent: int = counters.bytes_sent
        bytes_recv: int = counters.bytes_recv

        if self._prev_bytes_sent is None:
            # First call — establish baseline; nothing to persist yet.
            self._prev_bytes_sent = bytes_sent
            self._prev_bytes_recv = bytes_recv
            return

        delta_sent = bytes_sent - self._prev_bytes_sent
        delta_recv = bytes_recv - (self._prev_bytes_recv or 0)

        # Guard against counter resets (e.g., interface bounced).
        if delta_sent < 0:
            delta_sent = bytes_sent
        if delta_recv < 0:
            delta_recv = bytes_recv

        self._prev_bytes_sent = bytes_sent
        self._prev_bytes_recv = bytes_recv

        data: dict[str, Any] = {
            "bytes_sent": delta_sent,
            "bytes_recv": delta_recv,
        }

        try:
            repo = await self._get_metrics_repo()
            await repo.insert("network", data)
        except Exception:
            self.logger.exception("Failed to persist network metrics")
