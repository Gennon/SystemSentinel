from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class MetricStats:
    """Statistical summary for a single numeric metric over a time window."""

    average: float
    peak: float
    minimum: float
    threshold_exceeded: bool = False


@dataclass(frozen=True)
class NetworkAggregates:
    """Aggregated network I/O statistics for a time window."""

    bytes_sent: MetricStats
    bytes_recv: MetricStats


@dataclass(frozen=True)
class GpuAggregates:
    """Aggregated GPU statistics for a time window."""

    utilization_percent: MetricStats
    temperature_c: MetricStats
    power_draw_w: MetricStats | None = None
    vram_used_mb: MetricStats | None = None
    vram_total_mb: MetricStats | None = None


@dataclass(frozen=True)
class ProcessStats:
    """Average resource consumption for a named process over a time window."""

    name: str
    avg_cpu_percent: float
    avg_ram_bytes: float


@dataclass(frozen=True)
class DataGap:
    """A contiguous period within the collection window where no metrics were recorded."""

    start: datetime
    end: datetime

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()


@dataclass
class DailyAggregates:
    """All aggregated statistics for an arbitrary 24-hour window."""

    window_start: datetime
    window_end: datetime
    cpu: MetricStats | None
    ram: MetricStats | None
    disk: dict[str, MetricStats] = field(default_factory=dict)  # mountpoint -> stats
    network: NetworkAggregates | None = None
    gpu: GpuAggregates | None = None
    top_processes_by_cpu: list[ProcessStats] = field(default_factory=list)
    top_processes_by_ram: list[ProcessStats] = field(default_factory=list)
    gaps: list[DataGap] = field(default_factory=list)
    sample_count: int = 0
