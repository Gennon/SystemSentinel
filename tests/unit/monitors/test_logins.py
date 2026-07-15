from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.login_repository import LoginRepository
from system_sentinel.monitors.logins import (
    LoginMonitor,
    parse_failed_ssh_line,
    parse_successful_ssh_line,
)

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


def _make_ctx() -> AppContext:
    audit = AsyncMock()
    audit.append = AsyncMock()
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=audit,
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


@pytest.fixture
def default_config() -> dict:
    return {
        "enabled": True,
        "geoip_database_path": "",
        "failed_login_alert_count": 5,
        "failed_login_window": "00:10:00",
        "alert_cooldown": "00:30:00",
        "anomaly_detection": {
            "brute_force_enabled": True,
            "off_hours_enabled": True,
            "new_user_enabled": True,
            "impossible_travel_enabled": True,
            "off_hours_start": "07:00",
            "off_hours_end": "22:00",
            "impossible_travel_window": "02:00:00",
            "impossible_travel_min_distance_km": 500,
        },
    }


# ---------------------------------------------------------------------------
# parse_failed_ssh_line unit tests
# ---------------------------------------------------------------------------


def test_parse_standard_failed_password() -> None:
    line = "Failed password for root from 1.2.3.4 port 54321 ssh2"
    result = parse_failed_ssh_line(line)
    assert result is not None
    assert result["username"] == "root"
    assert result["ip_address"] == "1.2.3.4"
    assert result["port"] == 54321


def test_parse_invalid_user_failed_password() -> None:
    line = "Failed password for invalid user admin from 10.0.0.1 port 22 ssh2"
    result = parse_failed_ssh_line(line)
    assert result is not None
    assert result["username"] == "admin"
    assert result["ip_address"] == "10.0.0.1"
    assert result["port"] == 22


def test_parse_invalid_user_no_port() -> None:
    line = "Failed password for invalid user foo from 192.168.1.1 port 1234 ssh2"
    result = parse_failed_ssh_line(line)
    assert result is not None
    assert result["username"] == "foo"


def test_parse_returns_none_for_non_ssh_line() -> None:
    assert parse_failed_ssh_line("Accepted password for alice from 1.2.3.4 port 22 ssh2") is None
    assert parse_failed_ssh_line("sudo: alice : TTY=pts/0") is None
    assert parse_failed_ssh_line("") is None


def test_parse_connection_closed_line() -> None:
    line = "Connection closed by invalid user test 1.2.3.4 port 22 [preauth]"
    result = parse_failed_ssh_line(line)
    assert result is not None
    assert result["ip_address"] == "1.2.3.4"
    assert result["username"] == "test"


def test_parse_successful_password_login_line() -> None:
    line = "Accepted password for alice from 1.2.3.4 port 22 ssh2"
    result = parse_successful_ssh_line(line)
    assert result is not None
    assert result["username"] == "alice"
    assert result["ip_address"] == "1.2.3.4"
    assert result["port"] == 22
    assert result["auth_method"] == "password"


def test_parse_successful_publickey_login_line() -> None:
    line = "Accepted publickey for ubuntu from 2001:db8::1 port 2222 ssh2"
    result = parse_successful_ssh_line(line)
    assert result is not None
    assert result["username"] == "ubuntu"
    assert result["ip_address"] == "2001:db8::1"
    assert result["auth_method"] == "publickey"


def test_parse_successful_returns_none_for_non_success_line() -> None:
    assert parse_successful_ssh_line("Failed password for root from 1.2.3.4 port 22 ssh2") is None


# ---------------------------------------------------------------------------
# LoginMonitor integration tests (in-memory DB)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_stores_failed_attempt(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    log_lines = [
        "Failed password for root from 1.2.3.4 port 54321 ssh2",
    ]
    with patch.object(monitor, "_read_new_log_lines", return_value=log_lines):
        await monitor.collect()

    rows = await login_repo.unique_ips_since(datetime.now(UTC) - timedelta(minutes=5))
    assert len(rows) == 1
    assert rows[0]["ip_address"] == "1.2.3.4"
    assert rows[0]["attempts"] == 1


@pytest.mark.asyncio
async def test_collect_no_alert_below_threshold(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    log_lines = ["Failed password for root from 1.2.3.4 port 22 ssh2"] * 4  # threshold is 5
    with patch.object(monitor, "_read_new_log_lines", return_value=log_lines):
        await monitor.collect()

    ctx.event_bus.publish.assert_not_called()


@pytest.mark.asyncio
async def test_collect_triggers_alert_at_threshold(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    log_lines = ["Failed password for root from 1.2.3.4 port 22 ssh2"] * 5
    with patch.object(monitor, "_read_new_log_lines", return_value=log_lines):
        await monitor.collect()

    ctx.event_bus.publish.assert_called_once()
    event_type, payload = ctx.event_bus.publish.call_args[0]
    assert event_type == "alert.login.brute_force_detected"
    assert payload["ip_address"] == "1.2.3.4"
    assert payload["attempt_count"] == 5
    assert payload["event_type"] == "failed_ssh_logins"
    assert payload["current_value"] == "5"
    assert payload["threshold"] == ">=5 attempts within 10 minutes"
    assert "timestamp" in payload
    assert "hostname" in payload


@pytest.mark.asyncio
async def test_collect_alert_not_fired_twice_for_same_ip(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    log_lines = ["Failed password for root from 1.2.3.4 port 22 ssh2"] * 5
    with patch.object(monitor, "_read_new_log_lines", return_value=log_lines):
        await monitor.collect()
        await monitor.collect()

    assert ctx.event_bus.publish.call_count == 1


@pytest.mark.asyncio
async def test_collect_handles_empty_log(login_repo: LoginRepository, default_config: dict) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    with patch.object(monitor, "_read_new_log_lines", return_value=[]):
        await monitor.collect()  # must not raise

    ctx.event_bus.publish.assert_not_called()


@pytest.mark.asyncio
async def test_collect_skips_non_ssh_lines(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    log_lines = [
        "Accepted password for alice from 10.0.0.1 port 22 ssh2",
        "sudo: bob : TTY=pts/0 ; PWD=/home/bob",
    ]
    with patch.object(monitor, "_read_new_log_lines", return_value=log_lines):
        await monitor.collect()

    rows = await login_repo.unique_ips_since(datetime.now(UTC) - timedelta(minutes=5))
    assert len(rows) == 0


@pytest.mark.asyncio
async def test_collect_alert_includes_usernames(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    log_lines = [
        "Failed password for root from 1.2.3.4 port 22 ssh2",
        "Failed password for admin from 1.2.3.4 port 22 ssh2",
        "Failed password for invalid user test from 1.2.3.4 port 22 ssh2",
        "Failed password for ubuntu from 1.2.3.4 port 22 ssh2",
        "Failed password for pi from 1.2.3.4 port 22 ssh2",
    ]
    with patch.object(monitor, "_read_new_log_lines", return_value=log_lines):
        await monitor.collect()

    _, payload = ctx.event_bus.publish.call_args[0]
    assert set(payload["usernames"]) == {"root", "admin", "test", "ubuntu", "pi"}


@pytest.mark.asyncio
async def test_collect_triggers_new_user_anomaly(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = LoginMonitor(default_config, ctx, login_repo=login_repo)

    with patch.object(
        monitor,
        "_read_new_log_lines",
        return_value=["Accepted publickey for alice from 5.6.7.8 port 22 ssh2"],
    ):
        await monitor.collect()

    event_type, payload = ctx.event_bus.publish.call_args[0]
    assert event_type == "alert.login.new_user_detected"
    assert payload["username"] == "alice"
    assert payload["ip_address"] == "5.6.7.8"
    assert payload["anomaly_type"] == "new_user"


@pytest.mark.asyncio
async def test_collect_triggers_off_hours_anomaly(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    config = {
        **default_config,
        "anomaly_detection": {
            **default_config["anomaly_detection"],
            "off_hours_start": "23:00",
            "off_hours_end": "23:10",
        },
    }
    monitor = LoginMonitor(config, ctx, login_repo=login_repo)

    with patch.object(
        monitor,
        "_read_new_log_lines",
        return_value=["Accepted password for bob from 8.8.8.8 port 22 ssh2"],
    ):
        await monitor.collect()

    published_events = [call_args[0][0] for call_args in ctx.event_bus.publish.call_args_list]
    assert "alert.login.off_hours_detected" in published_events


@pytest.mark.asyncio
async def test_collect_triggers_impossible_travel_when_distance_exceeds_threshold(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    config = {
        **default_config,
        "geoip_database_path": "/tmp/GeoLite2-City.mmdb",
        "anomaly_detection": {
            **default_config["anomaly_detection"],
            "off_hours_enabled": False,
            "new_user_enabled": False,
            "impossible_travel_window": "03:00:00",
            "impossible_travel_min_distance_km": 500,
        },
    }
    monitor = LoginMonitor(config, ctx, login_repo=login_repo)

    with (
        patch.object(
            monitor,
            "_read_new_log_lines",
            return_value=[
                "Accepted password for carol from 1.1.1.1 port 22 ssh2",
                "Accepted password for carol from 8.8.8.8 port 22 ssh2",
            ],
        ),
        patch.object(monitor, "_distance_between_ips_km", return_value=1200.0),
    ):
        await monitor.collect()

    published_events = [call_args[0][0] for call_args in ctx.event_bus.publish.call_args_list]
    assert "alert.login.impossible_travel_detected" in published_events


@pytest.mark.asyncio
async def test_collect_skips_impossible_travel_when_geoip_unavailable(
    login_repo: LoginRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    config = {
        **default_config,
        "geoip_database_path": "",
        "anomaly_detection": {
            **default_config["anomaly_detection"],
            "off_hours_enabled": False,
            "new_user_enabled": False,
        },
    }
    monitor = LoginMonitor(config, ctx, login_repo=login_repo)

    with (
        patch.object(
            monitor,
            "_read_new_log_lines",
            return_value=[
                "Accepted password for dana from 9.9.9.9 port 22 ssh2",
                "Accepted password for dana from 8.8.4.4 port 22 ssh2",
            ],
        ),
        patch.object(monitor, "_distance_between_ips_km", return_value=None),
    ):
        await monitor.collect()

    published_events = [call_args[0][0] for call_args in ctx.event_bus.publish.call_args_list]
    assert "alert.login.impossible_travel_detected" not in published_events
