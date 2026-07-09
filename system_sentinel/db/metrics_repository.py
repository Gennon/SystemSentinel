from __future__ import annotations

from datetime import UTC, datetime
import json
from typing import TYPE_CHECKING, Any

from system_sentinel.db.aggregate_models import (
    DailyAggregates,
    DataGap,
    MetricStats,
    NetworkAggregates,
    ProcessStats,
)

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


def _compute_stats(
    values: list[float],
    threshold: float | None,
) -> MetricStats:
    avg = sum(values) / len(values)
    peak = max(values)
    minimum = min(values)
    exceeded = threshold is not None and peak > threshold
    return MetricStats(average=avg, peak=peak, minimum=minimum, threshold_exceeded=exceeded)


def _aggregate_processes(
    cpu_samples: list[dict[str, Any]],
) -> tuple[list[ProcessStats], list[ProcessStats]]:
    """Return top-5 processes by average CPU and RAM from CPU metric samples."""
    cpu_sum: dict[str, float] = {}
    ram_sum: dict[str, float] = {}
    count: dict[str, int] = {}

    for sample in cpu_samples:
        for proc in sample.get("top_processes", []):
            name = str(proc.get("name", "unknown"))
            cpu_sum[name] = cpu_sum.get(name, 0.0) + float(proc.get("cpu_percent", 0.0))
            ram_sum[name] = ram_sum.get(name, 0.0) + float(proc.get("ram_bytes", 0.0))
            count[name] = count.get(name, 0) + 1

    avgs = [
        ProcessStats(
            name=name,
            avg_cpu_percent=cpu_sum[name] / count[name],
            avg_ram_bytes=ram_sum[name] / count[name],
        )
        for name in cpu_sum
    ]

    top_by_cpu = sorted(avgs, key=lambda p: p.avg_cpu_percent, reverse=True)[:5]
    top_by_ram = sorted(avgs, key=lambda p: p.avg_ram_bytes, reverse=True)[:5]
    return top_by_cpu, top_by_ram


def _detect_gaps(
    timestamps: list[str],
    window_start: datetime,
    window_end: datetime,
    interval_seconds: int,
) -> list[DataGap]:
    """Find contiguous periods with no data within the collection window."""
    gap_threshold = interval_seconds * 1.5
    gaps: list[DataGap] = []

    if not timestamps:
        return [DataGap(start=window_start, end=window_end)]

    dts = [datetime.fromisoformat(ts) for ts in timestamps]

    if (dts[0] - window_start).total_seconds() > gap_threshold:
        gaps.append(DataGap(start=window_start, end=dts[0]))

    for i in range(1, len(dts)):
        if (dts[i] - dts[i - 1]).total_seconds() > gap_threshold:
            gaps.append(DataGap(start=dts[i - 1], end=dts[i]))

    if (window_end - dts[-1]).total_seconds() > gap_threshold:
        gaps.append(DataGap(start=dts[-1], end=window_end))

    return gaps


class MetricsRepository:
    """Stores and retrieves system metrics (US-005)."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def insert(
        self,
        metric_type: str,
        data: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> None:
        """Persist a single metric sample."""
        ts = (timestamp or datetime.now(UTC)).isoformat()
        await self._db.connection.execute(
            "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
            (ts, metric_type, json.dumps(data)),
        )
        await self._db.connection.commit()

    async def query_range(
        self,
        metric_type: str,
        since: datetime,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return all samples of *metric_type* in the given time range."""
        until = until or datetime.now(UTC)
        cursor = await self._db.connection.execute(
            "SELECT timestamp, data_json FROM system_metrics "
            "WHERE metric_type = ? AND timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp ASC",
            (metric_type, since.isoformat(), until.isoformat()),
        )
        rows = await cursor.fetchall()
        return [{"timestamp": row[0], **json.loads(row[1])} for row in rows]

    async def purge_old(self, metric_type: str | None, cutoff: datetime) -> int:
        """Delete records older than *cutoff*.  Pass ``None`` to purge all types.

        Returns the number of rows deleted.
        """
        if metric_type is None:
            cursor = await self._db.connection.execute(
                "DELETE FROM system_metrics WHERE timestamp < ?",
                (cutoff.isoformat(),),
            )
        else:
            cursor = await self._db.connection.execute(
                "DELETE FROM system_metrics WHERE metric_type = ? AND timestamp < ?",
                (metric_type, cutoff.isoformat()),
            )
        await self._db.connection.commit()
        return cursor.rowcount

    async def get_daily_aggregates(
        self,
        window_start: datetime,
        window_end: datetime | None = None,
        collection_interval_seconds: int = 60,
        thresholds: dict[str, float] | None = None,
    ) -> DailyAggregates:
        """Return 24-hour aggregates (avg, peak, min) for all metric types (US-006).

        Args:
            window_start: Start of the aggregation window (timezone-aware).
            window_end: End of the window; defaults to now (UTC).
            collection_interval_seconds: Expected interval between samples.
                Used to detect gaps in collection.
            thresholds: Optional per-metric alert thresholds.  Keys: ``"cpu"``,
                ``"ram"``, ``"disk"``, ``"network_bytes_sent"``,
                ``"network_bytes_recv"``.  A metric's
                :attr:`MetricStats.threshold_exceeded` is set to ``True`` when
                its peak value exceeded the given threshold during the window.
        """
        end = window_end or datetime.now(UTC)
        th = thresholds or {}

        cpu_samples = await self.query_range("cpu", since=window_start, until=end)
        ram_samples = await self.query_range("ram", since=window_start, until=end)
        disk_samples = await self.query_range("disk", since=window_start, until=end)
        network_samples = await self.query_range("network", since=window_start, until=end)

        # Unique timestamps across all types for gap detection and sample count.
        all_ts = sorted(
            {
                s["timestamp"]
                for samples in (cpu_samples, ram_samples, disk_samples, network_samples)
                for s in samples
            }
        )
        sample_count = len(all_ts)

        # --- CPU ---
        cpu_stats: MetricStats | None = None
        if cpu_samples:
            cpu_stats = _compute_stats(
                [float(s["overall_percent"]) for s in cpu_samples],
                th.get("cpu"),
            )

        # --- RAM ---
        ram_stats: MetricStats | None = None
        if ram_samples:
            ram_stats = _compute_stats(
                [float(s["percent"]) for s in ram_samples],
                th.get("ram"),
            )

        # --- Disk (per mountpoint) ---
        disk_values: dict[str, list[float]] = {}
        disk_exceeded: dict[str, bool] = {}
        disk_threshold = th.get("disk")
        for sample in disk_samples:
            for part in sample.get("partitions", []):
                mp: str = str(part["mountpoint"])
                pct = float(part["percent"])
                disk_values.setdefault(mp, []).append(pct)
                if disk_threshold is not None and pct > disk_threshold:
                    disk_exceeded[mp] = True

        disk_stats: dict[str, MetricStats] = {
            mp: MetricStats(
                average=sum(vals) / len(vals),
                peak=max(vals),
                minimum=min(vals),
                threshold_exceeded=disk_exceeded.get(mp, False),
            )
            for mp, vals in disk_values.items()
        }

        # --- Network ---
        network_stats: NetworkAggregates | None = None
        if network_samples:
            network_stats = NetworkAggregates(
                bytes_sent=_compute_stats(
                    [float(s["bytes_sent"]) for s in network_samples],
                    th.get("network_bytes_sent"),
                ),
                bytes_recv=_compute_stats(
                    [float(s["bytes_recv"]) for s in network_samples],
                    th.get("network_bytes_recv"),
                ),
            )

        # --- Top processes ---
        top_by_cpu, top_by_ram = _aggregate_processes(cpu_samples)

        # --- Gaps ---
        gaps = _detect_gaps(all_ts, window_start, end, collection_interval_seconds)

        return DailyAggregates(
            window_start=window_start,
            window_end=end,
            cpu=cpu_stats,
            ram=ram_stats,
            disk=disk_stats,
            network=network_stats,
            top_processes_by_cpu=top_by_cpu,
            top_processes_by_ram=top_by_ram,
            gaps=gaps,
            sample_count=sample_count,
        )
