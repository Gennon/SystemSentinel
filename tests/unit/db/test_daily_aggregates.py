"""Tests for MetricsRepository.get_daily_aggregates() (US-006)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db() -> DatabaseConnection:  # type: ignore[misc]
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn  # type: ignore[misc]
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> MetricsRepository:
    return MetricsRepository(db)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INTERVAL = 60  # seconds between samples


def _window(hours: int = 24) -> tuple[datetime, datetime]:
    end = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
    start = end - timedelta(hours=hours)
    return start, end


async def _insert_cpu(
    repo: MetricsRepository,
    base: datetime,
    count: int = 5,
    interval: int = _INTERVAL,
    overall_percents: list[float] | None = None,
    top_processes: list[dict[str, object]] | None = None,
) -> None:
    default_procs = [
        {"name": "proc_a", "pid": 1, "cpu_percent": 5.0, "ram_bytes": 100_000_000},
        {"name": "proc_b", "pid": 2, "cpu_percent": 3.0, "ram_bytes": 200_000_000},
    ]
    for i in range(count):
        ts = base + timedelta(seconds=i * interval)
        pct = overall_percents[i] if overall_percents else 10.0 + i
        await repo.insert(
            "cpu",
            {
                "overall_percent": pct,
                "per_core_percent": [pct],
                "top_processes": top_processes if top_processes is not None else default_procs,
            },
            timestamp=ts,
        )


async def _insert_ram(
    repo: MetricsRepository,
    base: datetime,
    count: int = 5,
    interval: int = _INTERVAL,
    percents: list[float] | None = None,
) -> None:
    for i in range(count):
        ts = base + timedelta(seconds=i * interval)
        pct = percents[i] if percents else 40.0 + i
        await repo.insert(
            "ram",
            {
                "total_bytes": 8_000_000_000,
                "used_bytes": 3_000_000_000,
                "available_bytes": 5_000_000_000,
                "percent": pct,
            },
            timestamp=ts,
        )


async def _insert_disk(
    repo: MetricsRepository,
    base: datetime,
    count: int = 5,
    interval: int = _INTERVAL,
    percents: list[float] | None = None,
) -> None:
    for i in range(count):
        ts = base + timedelta(seconds=i * interval)
        pct = percents[i] if percents else 60.0 + i
        await repo.insert(
            "disk",
            {
                "partitions": [
                    {
                        "mountpoint": "/",
                        "device": "/dev/sda1",
                        "fstype": "ext4",
                        "total_bytes": 100_000_000_000,
                        "used_bytes": 60_000_000_000,
                        "free_bytes": 40_000_000_000,
                        "percent": pct,
                    }
                ]
            },
            timestamp=ts,
        )


async def _insert_network(
    repo: MetricsRepository,
    base: datetime,
    count: int = 5,
    interval: int = _INTERVAL,
) -> None:
    for i in range(count):
        ts = base + timedelta(seconds=i * interval)
        await repo.insert(
            "network",
            {"bytes_sent": 1000 * (i + 1), "bytes_recv": 2000 * (i + 1)},
            timestamp=ts,
        )


# ---------------------------------------------------------------------------
# AC: basic stats for each metric type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cpu_stats_avg_peak_min(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_cpu(repo, base, count=3, overall_percents=[10.0, 20.0, 30.0])

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert result.cpu is not None
    assert result.cpu.average == pytest.approx(20.0)
    assert result.cpu.peak == pytest.approx(30.0)
    assert result.cpu.minimum == pytest.approx(10.0)


@pytest.mark.asyncio
async def test_ram_stats_avg_peak_min(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_ram(repo, base, count=3, percents=[40.0, 60.0, 50.0])

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert result.ram is not None
    assert result.ram.average == pytest.approx(50.0)
    assert result.ram.peak == pytest.approx(60.0)
    assert result.ram.minimum == pytest.approx(40.0)


@pytest.mark.asyncio
async def test_disk_stats_per_mountpoint(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_disk(repo, base, count=3, percents=[50.0, 70.0, 60.0])

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert "/" in result.disk
    stats = result.disk["/"]
    assert stats.average == pytest.approx(60.0)
    assert stats.peak == pytest.approx(70.0)
    assert stats.minimum == pytest.approx(50.0)


@pytest.mark.asyncio
async def test_network_stats_bytes_sent_and_recv(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_network(repo, base, count=3)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert result.network is not None
    assert result.network.bytes_sent.average == pytest.approx(2000.0)  # (1000+2000+3000)/3
    assert result.network.bytes_sent.peak == pytest.approx(3000.0)
    assert result.network.bytes_recv.average == pytest.approx(4000.0)  # (2000+4000+6000)/3
    assert result.network.bytes_recv.peak == pytest.approx(6000.0)


# ---------------------------------------------------------------------------
# AC: top-5 processes by avg CPU and RAM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_top_processes_by_cpu(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)

    procs = [
        {"name": "heavy", "pid": 1, "cpu_percent": 80.0, "ram_bytes": 100_000},
        {"name": "medium", "pid": 2, "cpu_percent": 40.0, "ram_bytes": 200_000},
        {"name": "light", "pid": 3, "cpu_percent": 5.0, "ram_bytes": 300_000},
    ]
    await _insert_cpu(repo, base, count=2, top_processes=procs)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert len(result.top_processes_by_cpu) >= 1
    assert result.top_processes_by_cpu[0].name == "heavy"
    assert result.top_processes_by_cpu[0].avg_cpu_percent == pytest.approx(80.0)


@pytest.mark.asyncio
async def test_top_processes_by_ram(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)

    procs = [
        {"name": "mem_hog", "pid": 1, "cpu_percent": 5.0, "ram_bytes": 900_000_000},
        {"name": "medium", "pid": 2, "cpu_percent": 40.0, "ram_bytes": 200_000_000},
    ]
    await _insert_cpu(repo, base, count=2, top_processes=procs)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert len(result.top_processes_by_ram) >= 1
    assert result.top_processes_by_ram[0].name == "mem_hog"
    assert result.top_processes_by_ram[0].avg_ram_bytes == pytest.approx(900_000_000.0)


@pytest.mark.asyncio
async def test_top_processes_capped_at_five(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)

    procs = [
        {"name": f"proc_{i}", "pid": i, "cpu_percent": float(10 - i), "ram_bytes": i * 1_000_000}
        for i in range(8)
    ]
    await _insert_cpu(repo, base, count=1, top_processes=procs)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert len(result.top_processes_by_cpu) <= 5
    assert len(result.top_processes_by_ram) <= 5


@pytest.mark.asyncio
async def test_top_processes_averaged_across_samples(repo: MetricsRepository) -> None:
    """Same process appearing in multiple samples is averaged, not duplicated."""
    start, end = _window()
    base = start + timedelta(minutes=1)

    await repo.insert(
        "cpu",
        {
            "overall_percent": 20.0,
            "per_core_percent": [20.0],
            "top_processes": [{"name": "worker", "pid": 1, "cpu_percent": 10.0, "ram_bytes": 100}],
        },
        timestamp=base,
    )
    await repo.insert(
        "cpu",
        {
            "overall_percent": 30.0,
            "per_core_percent": [30.0],
            "top_processes": [{"name": "worker", "pid": 1, "cpu_percent": 30.0, "ram_bytes": 200}],
        },
        timestamp=base + timedelta(seconds=60),
    )

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    # "worker" should appear exactly once with averaged values
    workers = [p for p in result.top_processes_by_cpu if p.name == "worker"]
    assert len(workers) == 1
    assert workers[0].avg_cpu_percent == pytest.approx(20.0)  # (10+30)/2
    assert workers[0].avg_ram_bytes == pytest.approx(150.0)  # (100+200)/2


# ---------------------------------------------------------------------------
# AC: threshold exceedance flagging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threshold_not_exceeded(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_cpu(repo, base, count=3, overall_percents=[10.0, 20.0, 30.0])

    result = await repo.get_daily_aggregates(
        start,
        end,
        collection_interval_seconds=_INTERVAL,
        thresholds={"cpu": 90.0},
    )

    assert result.cpu is not None
    assert result.cpu.threshold_exceeded is False


@pytest.mark.asyncio
async def test_threshold_exceeded_when_peak_above(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_cpu(repo, base, count=3, overall_percents=[10.0, 95.0, 20.0])

    result = await repo.get_daily_aggregates(
        start,
        end,
        collection_interval_seconds=_INTERVAL,
        thresholds={"cpu": 90.0},
    )

    assert result.cpu is not None
    assert result.cpu.threshold_exceeded is True


@pytest.mark.asyncio
async def test_threshold_exceeded_for_disk(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_disk(repo, base, count=2, percents=[50.0, 95.0])

    result = await repo.get_daily_aggregates(
        start,
        end,
        collection_interval_seconds=_INTERVAL,
        thresholds={"disk": 90.0},
    )

    assert result.disk["/"].threshold_exceeded is True


@pytest.mark.asyncio
async def test_threshold_not_exceeded_for_disk(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_disk(repo, base, count=2, percents=[50.0, 70.0])

    result = await repo.get_daily_aggregates(
        start,
        end,
        collection_interval_seconds=_INTERVAL,
        thresholds={"disk": 90.0},
    )

    assert result.disk["/"].threshold_exceeded is False


# ---------------------------------------------------------------------------
# AC: gap detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_gaps_when_data_is_continuous(repo: MetricsRepository) -> None:
    start, end = _window()
    # Insert 1440 samples (one per minute) starting 30s into the window.
    # Last sample lands at start + 30 + 1439*60 = start + 86370s, which is
    # only 30s before window end — within the 90s gap threshold.
    base = start + timedelta(seconds=30)
    await _insert_cpu(repo, base, count=1440, interval=60)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=60)

    assert result.gaps == []


@pytest.mark.asyncio
async def test_gap_detected_in_middle(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(seconds=30)

    # Two clusters of samples with a 2-hour gap in between
    await _insert_cpu(repo, base, count=5, interval=60)
    gap_start = base + timedelta(seconds=4 * 60)
    gap_end = gap_start + timedelta(hours=2)
    await _insert_cpu(repo, gap_end, count=5, interval=60)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=60)

    assert len(result.gaps) >= 1
    gap = result.gaps[0]
    assert gap.duration_seconds > 60 * 60  # at least 1 hour


@pytest.mark.asyncio
async def test_gap_at_window_start(repo: MetricsRepository) -> None:
    start, end = _window()
    # First sample is 2 hours after window start
    base = start + timedelta(hours=2)
    await _insert_cpu(repo, base, count=5, interval=60)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=60)

    gap_starts = [g for g in result.gaps if g.start == start]
    assert len(gap_starts) == 1
    assert gap_starts[0].duration_seconds >= 2 * 3600 - 90  # ~2h


@pytest.mark.asyncio
async def test_gap_at_window_end(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(seconds=30)
    # Only 5 samples at the very start, then nothing for the rest
    await _insert_cpu(repo, base, count=5, interval=60)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=60)

    gap_ends = [g for g in result.gaps if g.end == end]
    assert len(gap_ends) == 1
    assert gap_ends[0].duration_seconds > 3600  # at least 1 hour


@pytest.mark.asyncio
async def test_entire_window_is_gap_when_no_data(repo: MetricsRepository) -> None:
    start, end = _window()

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=60)

    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.start == start
    assert gap.end == end


# ---------------------------------------------------------------------------
# AC: queryable for arbitrary window, not just current day
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_arbitrary_window_yesterday(repo: MetricsRepository) -> None:
    """Data from a past window should be aggregated, current-day data excluded."""
    now = datetime(2024, 6, 3, 12, 0, 0, tzinfo=UTC)
    yesterday_start = now - timedelta(hours=48)
    yesterday_end = now - timedelta(hours=24)
    today_start = yesterday_end

    base_yesterday = yesterday_start + timedelta(minutes=1)
    await _insert_cpu(repo, base_yesterday, count=3, overall_percents=[10.0, 20.0, 30.0])

    base_today = today_start + timedelta(minutes=1)
    await _insert_cpu(repo, base_today, count=3, overall_percents=[50.0, 60.0, 70.0])

    result = await repo.get_daily_aggregates(
        yesterday_start, yesterday_end, collection_interval_seconds=_INTERVAL
    )

    assert result.cpu is not None
    assert result.cpu.average == pytest.approx(20.0)  # yesterday data only
    assert result.cpu.peak == pytest.approx(30.0)


# ---------------------------------------------------------------------------
# AC: missing metric types return None / empty
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_cpu_data_returns_none(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_ram(repo, base)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert result.cpu is None


@pytest.mark.asyncio
async def test_no_network_data_returns_none(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_cpu(repo, base)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert result.network is None


@pytest.mark.asyncio
async def test_no_disk_data_returns_empty_dict(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_cpu(repo, base)

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert result.disk == {}


# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sample_count_reflects_total_distinct_timestamps(repo: MetricsRepository) -> None:
    start, end = _window()
    base = start + timedelta(minutes=1)
    await _insert_cpu(repo, base, count=3)
    await _insert_ram(repo, base, count=3)  # same timestamps → 3 distinct

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    # 3 unique timestamps (cpu and ram inserted at same times)
    assert result.sample_count == 3


@pytest.mark.asyncio
async def test_window_boundaries_stored_on_result(repo: MetricsRepository) -> None:
    start, end = _window()

    result = await repo.get_daily_aggregates(start, end, collection_interval_seconds=_INTERVAL)

    assert result.window_start == start
    assert result.window_end == end
