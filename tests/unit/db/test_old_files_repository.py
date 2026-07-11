from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.old_files_repository import OldFilesRepository


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> OldFilesRepository:
    return OldFilesRepository(db)


@pytest.mark.asyncio
async def test_record_scan_persists_summary_and_file_rows(repo: OldFilesRepository) -> None:
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    files = [
        {
            "file_path": "/tmp/a.log",
            "size_bytes": 100,
            "last_modified": "2026-06-01T00:00:00+00:00",
            "age_days": 40,
        },
        {
            "file_path": "/tmp/b.log",
            "size_bytes": 50,
            "last_modified": "2026-06-15T00:00:00+00:00",
            "age_days": 26,
        },
    ]

    summary = await repo.record_scan("/tmp", age_threshold_days=20, scanned_at=now, files=files)
    rows = await repo.files_for_latest_scan("/tmp")

    assert summary["file_count"] == 2
    assert summary["total_size_bytes"] == 150
    assert len(rows) == 2
    assert rows[0]["file_path"] == "/tmp/a.log"
    assert rows[0]["size_bytes"] == 100
    assert rows[0]["age_days"] == 40


@pytest.mark.asyncio
async def test_latest_scan_summaries_returns_latest_per_directory(
    repo: OldFilesRepository,
) -> None:
    now = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
    await repo.record_scan(
        "/tmp/a",
        age_threshold_days=10,
        scanned_at=now - timedelta(hours=2),
        files=[],
    )
    await repo.record_scan(
        "/tmp/a",
        age_threshold_days=10,
        scanned_at=now - timedelta(hours=1),
        files=[
            {
                "file_path": "/tmp/a/old.log",
                "size_bytes": 12,
                "last_modified": now.isoformat(),
                "age_days": 10,
            }
        ],
    )
    await repo.record_scan(
        "/tmp/b",
        age_threshold_days=10,
        scanned_at=now - timedelta(minutes=30),
        files=[],
    )

    summaries = await repo.latest_scan_summaries(now - timedelta(hours=24))

    assert len(summaries) == 2
    by_dir = {row["watched_directory"]: row for row in summaries}
    assert by_dir["/tmp/a"]["file_count"] == 1
    assert by_dir["/tmp/b"]["file_count"] == 0


@pytest.mark.asyncio
async def test_state_roundtrip(repo: OldFilesRepository) -> None:
    assert await repo.get_state("old_files.daily_report.last_sent_date_utc") is None
    await repo.set_state("old_files.daily_report.last_sent_date_utc", "2026-07-11")
    value = await repo.get_state("old_files.daily_report.last_sent_date_utc")
    assert value == "2026-07-11"
