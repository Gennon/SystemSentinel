from __future__ import annotations

from datetime import UTC, datetime

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.directory_changes_repository import DirectoryChangesRepository


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> DirectoryChangesRepository:
    return DirectoryChangesRepository(db)


@pytest.mark.asyncio
async def test_record_event_and_recent_roundtrip(repo: DirectoryChangesRepository) -> None:
    now = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
    await repo.record_event(
        observed_at=now,
        watched_directory="/var/log",
        change_type="created",
        file_path="/var/log/app.log",
        destination_path=None,
        process_owner="root",
        alert_suppressed=False,
        suppression_reason=None,
    )

    rows = await repo.recent_events(limit=1)
    assert len(rows) == 1
    assert rows[0]["watched_directory"] == "/var/log"
    assert rows[0]["change_type"] == "created"
    assert rows[0]["file_path"] == "/var/log/app.log"
    assert rows[0]["process_owner"] == "root"
    assert rows[0]["alert_suppressed"] is False


@pytest.mark.asyncio
async def test_recent_returns_newest_first(repo: DirectoryChangesRepository) -> None:
    await repo.record_event(
        observed_at=datetime(2026, 7, 16, 12, 0, tzinfo=UTC),
        watched_directory="/tmp",
        change_type="modified",
        file_path="/tmp/a",
        destination_path=None,
        process_owner=None,
        alert_suppressed=False,
        suppression_reason=None,
    )
    await repo.record_event(
        observed_at=datetime(2026, 7, 16, 12, 1, tzinfo=UTC),
        watched_directory="/tmp",
        change_type="deleted",
        file_path="/tmp/a",
        destination_path=None,
        process_owner=None,
        alert_suppressed=True,
        suppression_reason="cooldown",
    )

    rows = await repo.recent_events(limit=2)
    assert rows[0]["change_type"] == "deleted"
    assert rows[0]["suppression_reason"] == "cooldown"
    assert rows[1]["change_type"] == "modified"
