from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from system_sentinel.chat.base import AlertSeverity
from system_sentinel.chat.digest_builder import DigestBuilder
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.login_repository import LoginRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
async def login_repo(db: DatabaseConnection) -> LoginRepository:
    return LoginRepository(db)


# ---------------------------------------------------------------------------
# DigestBuilder tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_login_digest_returns_none_when_no_data(
    login_repo: LoginRepository,
) -> None:
    builder = DigestBuilder()
    since = datetime.now(UTC) - timedelta(hours=24)
    result = await builder.build_login_digest(login_repo, since)
    assert result is None


@pytest.mark.asyncio
async def test_build_login_digest_lists_attacking_ips(
    login_repo: LoginRepository,
) -> None:
    now = datetime.now(UTC)
    await login_repo.record(ip_address="10.0.0.1", username="root", timestamp=now, port=22)
    await login_repo.record(ip_address="10.0.0.2", username="admin", timestamp=now, port=22)
    await login_repo.record(ip_address="10.0.0.1", username="ubuntu", timestamp=now, port=22)

    builder = DigestBuilder()
    since = now - timedelta(hours=1)
    result = await builder.build_login_digest(login_repo, since)

    assert result is not None
    assert "10.0.0.1" in result.text
    assert "10.0.0.2" in result.text


@pytest.mark.asyncio
async def test_build_login_digest_shows_attempt_counts(
    login_repo: LoginRepository,
) -> None:
    now = datetime.now(UTC)
    for _ in range(3):
        await login_repo.record(ip_address="5.5.5.5", username="root", timestamp=now, port=22)

    builder = DigestBuilder()
    result = await builder.build_login_digest(login_repo, now - timedelta(hours=1))

    assert result is not None
    assert "3" in result.text


@pytest.mark.asyncio
async def test_build_login_digest_severity_is_warning(
    login_repo: LoginRepository,
) -> None:
    now = datetime.now(UTC)
    await login_repo.record(ip_address="1.1.1.1", username="root", timestamp=now, port=22)

    builder = DigestBuilder()
    result = await builder.build_login_digest(login_repo, now - timedelta(hours=1))

    assert result is not None
    assert result.severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_build_login_digest_fields_contain_unique_ip_count(
    login_repo: LoginRepository,
) -> None:
    now = datetime.now(UTC)
    for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
        await login_repo.record(ip_address=ip, username="root", timestamp=now, port=22)

    builder = DigestBuilder()
    result = await builder.build_login_digest(login_repo, now - timedelta(hours=1))

    assert result is not None
    assert result.fields is not None
    assert result.fields["Unique IPs"] == "3"


@pytest.mark.asyncio
async def test_build_login_digest_excludes_old_records(
    login_repo: LoginRepository,
) -> None:
    old = datetime.now(UTC) - timedelta(hours=48)
    await login_repo.record(ip_address="9.9.9.9", username="root", timestamp=old, port=22)

    builder = DigestBuilder()
    since = datetime.now(UTC) - timedelta(hours=24)
    result = await builder.build_login_digest(login_repo, since)

    assert result is None


@pytest.mark.asyncio
async def test_build_login_digest_defaults_to_last_24h(
    login_repo: LoginRepository,
) -> None:
    now = datetime.now(UTC)
    await login_repo.record(ip_address="7.7.7.7", username="root", timestamp=now, port=22)

    builder = DigestBuilder()
    result = await builder.build_login_digest(login_repo)  # no `since` arg

    assert result is not None
    assert "7.7.7.7" in result.text
