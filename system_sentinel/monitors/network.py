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
        await self._maybe_emit_alert(data)

        try:
            repo = await self._get_metrics_repo()
            await repo.insert("network", data)
        except Exception:
            self.logger.exception("Failed to persist network metrics")

    async def _maybe_emit_alert(self, data: dict[str, Any]) -> None:
        sent_threshold_raw = self.config.get("alert_threshold_bytes_sent")
        recv_threshold_raw = self.config.get("alert_threshold_bytes_recv")
        if sent_threshold_raw is None and recv_threshold_raw is None:
            return

        sent_threshold = float(sent_threshold_raw) if sent_threshold_raw is not None else None
        recv_threshold = float(recv_threshold_raw) if recv_threshold_raw is not None else None

        bytes_sent = int(data.get("bytes_sent", 0))
        bytes_recv = int(data.get("bytes_recv", 0))
        triggered_metrics: list[str] = []
        if sent_threshold is not None and bytes_sent > sent_threshold:
            triggered_metrics.append("bytes_sent")
        if recv_threshold is not None and bytes_recv > recv_threshold:
            triggered_metrics.append("bytes_recv")
        if not triggered_metrics:
            return

        cooldown_seconds = parse_duration_from_config(
            self.config,
            key="alert_cooldown",
            default_seconds=30 * 60,
            logger=self.logger,
        )
        now = datetime.now(UTC)
        if (
            self._last_alert_at is not None
            and (now - self._last_alert_at).total_seconds() < cooldown_seconds
        ):
            return

        sent_threshold_label = (
            f"sent>{int(sent_threshold)} B/interval"
            if sent_threshold is not None
            else "sent=disabled"
        )
        recv_threshold_label = (
            f"recv>{int(recv_threshold)} B/interval"
            if recv_threshold is not None
            else "recv=disabled"
        )

        await self.ctx.event_bus.publish(
            "alert.network.throughput_threshold_exceeded",
            {
                "event_type": "network_throughput_threshold_exceeded",
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "threshold": f"{sent_threshold_label} or {recv_threshold_label}",
                "triggered_metrics": triggered_metrics,
                "timestamp": now.isoformat(),
                "hostname": socket.gethostname(),
            },
        )
        self._last_alert_at = now
