from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
import os
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.old_files_repository import OldFilesRepository
from system_sentinel.monitors.old_files import OldFilesMonitor

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> OldFilesRepository:
    return OldFilesRepository(db)


def _make_ctx() -> AppContext:
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=AsyncMock(),
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


def _make_file(path: Path, *, days_old: int, size: int) -> None:
    path.write_bytes(b"x" * size)
    ts = (datetime.now(UTC) - timedelta(days=days_old)).timestamp()
    os.utime(path, (ts, ts))


@pytest.mark.asyncio
async def test_collect_stores_only_files_older_than_threshold(
    repo: OldFilesRepository, tmp_path: Path
) -> None:
    old_file = tmp_path / "old.log"
    new_file = tmp_path / "new.log"
    _make_file(old_file, days_old=30, size=128)
    _make_file(new_file, days_old=1, size=64)

    config = {
        "enabled": True,
        "watched_directories": [str(tmp_path)],
        "age_threshold": "7d 00:00:00",
        "scan_interval": "24:00:00",
        "daily_report_time_utc": "23:59",
    }
    monitor = OldFilesMonitor(config, _make_ctx(), old_files_repo=repo)
    await monitor.collect()

    rows = await repo.files_for_latest_scan(str(tmp_path))
    assert len(rows) == 1
    assert rows[0]["file_path"] == str(old_file)
    assert rows[0]["size_bytes"] == 128
    assert rows[0]["age_days"] >= 30


@pytest.mark.asyncio
async def test_collect_expands_tilde_in_watched_directories(
    repo: OldFilesRepository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home_dir = tmp_path / "home"
    watched_dir = home_dir / "archive"
    watched_dir.mkdir(parents=True)
    old_file = watched_dir / "old.log"
    _make_file(old_file, days_old=40, size=32)
    monkeypatch.setenv("HOME", str(home_dir))

    config = {
        "enabled": True,
        "watched_directories": ["~/archive"],
        "age_threshold": "7d 00:00:00",
        "scan_interval": "24:00:00",
        "daily_report_time_utc": "23:59",
    }
    monitor = OldFilesMonitor(config, _make_ctx(), old_files_repo=repo)
    await monitor.collect()

    rows = await repo.files_for_latest_scan(str(watched_dir))
    assert len(rows) == 1
    assert rows[0]["file_path"] == str(old_file)


@pytest.mark.asyncio
async def test_collect_respects_scan_interval(repo: OldFilesRepository, tmp_path: Path) -> None:
    old_file = tmp_path / "old.log"
    _make_file(old_file, days_old=10, size=10)

    config = {
        "enabled": True,
        "watched_directories": [str(tmp_path)],
        "age_threshold": "7d 00:00:00",
        "scan_interval": "24:00:00",
        "daily_report_time_utc": "23:59",
    }
    monitor = OldFilesMonitor(config, _make_ctx(), old_files_repo=repo)

    await monitor.collect()
    await monitor.collect()  # second run is within interval -> no second scan insert

    cursor = await repo._db.connection.execute("SELECT COUNT(*) FROM old_file_scans")
    row = await cursor.fetchone()
    assert row is not None
    assert int(row[0]) == 1


@pytest.mark.asyncio
async def test_collect_publishes_daily_digest_once_per_day(
    repo: OldFilesRepository, tmp_path: Path
) -> None:
    old_file = tmp_path / "old.log"
    _make_file(old_file, days_old=20, size=256)

    ctx = _make_ctx()
    config = {
        "enabled": True,
        "watched_directories": [str(tmp_path)],
        "age_threshold": "7d 00:00:00",
        "scan_interval": "24:00:00",
        "daily_report_time_utc": "00:00",
    }
    monitor = OldFilesMonitor(config, ctx, old_files_repo=repo)

    await monitor.collect()
    await monitor.collect()

    event_types = [call.args[0] for call in ctx.event_bus.publish.call_args_list]
    assert event_types.count("alert.files.daily_digest") == 1
