from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from system_sentinel.db.audit_repository import SqliteAuditRepository
from system_sentinel.db.connection import DatabaseConnection

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path: pytest.TempPathFactory) -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> SqliteAuditRepository:
    return SqliteAuditRepository(db)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_stores_entry(repo: SqliteAuditRepository) -> None:
    await repo.append(
        action_type="tool_run",
        source="scheduler",
        description="Security update completed.",
        outcome="success",
    )
    rows = await repo.recent(limit=1)
    assert len(rows) == 1
    assert rows[0]["action_type"] == "tool_run"
    assert rows[0]["source"] == "scheduler"
    assert rows[0]["description"] == "Security update completed."
    assert rows[0]["outcome"] == "success"
    assert rows[0]["details_json"] is None


@pytest.mark.asyncio
async def test_append_serialises_details(repo: SqliteAuditRepository) -> None:
    details = {"packages": ["curl", "openssh-server"], "count": 2}
    await repo.append(
        action_type="tool_run",
        source="scheduler",
        description="2 packages updated.",
        outcome="success",
        details=details,
    )
    rows = await repo.recent(limit=1)
    assert rows[0]["details_json"] is not None
    assert json.loads(rows[0]["details_json"]) == details


@pytest.mark.asyncio
async def test_recent_returns_newest_first(repo: SqliteAuditRepository) -> None:
    for i in range(3):
        await repo.append(
            action_type="tool_run",
            source="scheduler",
            description=f"Entry {i}",
            outcome="success",
        )
    rows = await repo.recent(limit=3)
    descriptions = [r["description"] for r in rows]
    assert descriptions == ["Entry 2", "Entry 1", "Entry 0"]


@pytest.mark.asyncio
async def test_recent_respects_limit(repo: SqliteAuditRepository) -> None:
    for i in range(5):
        await repo.append(
            action_type="tool_run",
            source="scheduler",
            description=f"Entry {i}",
            outcome="success",
        )
    rows = await repo.recent(limit=2)
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_audit_log_is_append_only(
    repo: SqliteAuditRepository, db: DatabaseConnection
) -> None:
    await repo.append(
        action_type="tool_run",
        source="scheduler",
        description="Original entry.",
        outcome="success",
    )
    with pytest.raises(Exception, match="append-only"):
        await db.connection.execute("UPDATE audit_log SET description = 'tampered'")
        await db.connection.commit()

    with pytest.raises(Exception, match="append-only"):
        await db.connection.execute("DELETE FROM audit_log")
        await db.connection.commit()


@pytest.mark.asyncio
async def test_timestamp_is_iso8601_utc(repo: SqliteAuditRepository) -> None:
    await repo.append(
        action_type="config_reload",
        source="daemon",
        description="Config reloaded.",
        outcome="success",
    )
    rows = await repo.recent(limit=1)
    timestamp = rows[0]["timestamp"]
    assert "T" in timestamp
    assert timestamp.endswith("+00:00") or timestamp.endswith("Z")


@pytest.mark.asyncio
async def test_append_mirrors_entry_to_text_log(tmp_path: Path, db: DatabaseConnection) -> None:
    text_log_path = tmp_path / "audit.log"
    audit_repo = SqliteAuditRepository(db, text_log_path=text_log_path)

    await audit_repo.append(
        action_type="tool_run",
        source="scheduler",
        description="Security update completed.",
        outcome="success",
    )

    content = text_log_path.read_text(encoding="utf-8")
    assert "tool_run" in content
    assert "success" in content
    assert "scheduler" in content
    assert "Security update completed." in content


@pytest.mark.asyncio
async def test_append_text_log_failure_is_tolerated_and_db_entry_persists(
    tmp_path: Path, db: DatabaseConnection
) -> None:
    """Text file mirroring is best-effort; a write failure must not roll back the SQLite entry."""
    text_log_dir = tmp_path / "audit.log"
    text_log_dir.mkdir()  # make path a directory so open("a") raises IsADirectoryError
    audit_repo = SqliteAuditRepository(db, text_log_path=text_log_dir)

    # Should NOT raise — text file failure is logged and swallowed
    await audit_repo.append(
        action_type="tool_run",
        source="scheduler",
        description="Should persist in SQLite even though text log failed.",
        outcome="success",
    )

    rows = await audit_repo.recent(limit=1)
    assert len(rows) == 1
    assert rows[0]["description"] == "Should persist in SQLite even though text log failed."
