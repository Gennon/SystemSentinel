from __future__ import annotations

from datetime import UTC, datetime

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.file_integrity_repository import FileIntegrityRepository


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> FileIntegrityRepository:
    return FileIntegrityRepository(db)


@pytest.mark.asyncio
async def test_upsert_baseline_and_get_status(repo: FileIntegrityRepository) -> None:
    observed_at = datetime(2026, 7, 27, 10, 0, tzinfo=UTC)
    await repo.upsert_baseline(
        path="/etc/passwd",
        source_path="/etc/passwd",
        expected_sha256="abc123",
        observed_at=observed_at,
    )

    baseline = await repo.get_baseline("/etc/passwd")
    assert baseline is not None
    assert baseline["path"] == "/etc/passwd"
    assert baseline["expected_sha256"] == "abc123"

    statuses = await repo.list_statuses(["/etc/passwd"])
    assert len(statuses) == 1
    assert statuses[0]["source_path"] == "/etc/passwd"


@pytest.mark.asyncio
async def test_record_verification_updates_last_status(repo: FileIntegrityRepository) -> None:
    observed_at = datetime(2026, 7, 27, 10, 0, tzinfo=UTC)
    await repo.upsert_baseline(
        path="/etc/ssh/sshd_config",
        source_path="/etc/ssh/sshd_config",
        expected_sha256="expected",
        observed_at=observed_at,
    )
    checked_at = datetime(2026, 7, 27, 10, 5, tzinfo=UTC)
    await repo.record_verification(
        path="/etc/ssh/sshd_config",
        checked_at=checked_at,
        expected_sha256="expected",
        actual_sha256="actual",
        status="mismatch",
    )

    baseline = await repo.get_baseline("/etc/ssh/sshd_config")
    assert baseline is not None
    assert baseline["last_status"] == "mismatch"
    assert baseline["last_actual_sha256"] == "actual"
    assert baseline["last_verified_at"] == checked_at.isoformat()
