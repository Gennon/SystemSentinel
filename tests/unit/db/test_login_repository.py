from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.login_repository import LoginRepository


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db: DatabaseConnection) -> LoginRepository:
    return LoginRepository(db)


@pytest.mark.asyncio
async def test_record_successful_login_and_has_successful_login(repo: LoginRepository) -> None:
    now = datetime.now(UTC)
    await repo.record_successful_login(
        ip_address="1.2.3.4",
        username="alice",
        timestamp=now,
        port=22,
        auth_method="password",
    )
    assert await repo.has_successful_login("alice") is True
    assert await repo.has_successful_login("bob") is False


@pytest.mark.asyncio
async def test_latest_successful_login_for_user_with_window(repo: LoginRepository) -> None:
    older = datetime.now(UTC) - timedelta(hours=2)
    newer = datetime.now(UTC) - timedelta(minutes=10)
    await repo.record_successful_login(
        ip_address="10.0.0.1",
        username="alice",
        timestamp=older,
        port=22,
        auth_method="password",
    )
    await repo.record_successful_login(
        ip_address="203.0.113.5",
        username="alice",
        timestamp=newer,
        port=22,
        auth_method="publickey",
    )

    row = await repo.latest_successful_login_for_user(
        "alice",
        before=datetime.now(UTC),
        since=datetime.now(UTC) - timedelta(hours=1),
    )
    assert row is not None
    assert row["ip_address"] == "203.0.113.5"
    assert row["auth_method"] == "publickey"


@pytest.mark.asyncio
async def test_record_and_query_login_anomalies(repo: LoginRepository) -> None:
    now = datetime.now(UTC)
    await repo.record_anomaly(
        observed_at=now,
        anomaly_type="off_hours",
        username="alice",
        ip_address="1.2.3.4",
        details={"anomaly_type": "off_hours", "allowed_hours": "07:00-22:00"},
    )

    rows = await repo.anomalies_since(now - timedelta(minutes=1))
    assert len(rows) == 1
    assert rows[0]["anomaly_type"] == "off_hours"
    assert rows[0]["username"] == "alice"
    assert rows[0]["details"]["allowed_hours"] == "07:00-22:00"
