from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.monitors.connections import (
    ConnectionMonitor,
    is_whitelisted,
    parse_ss_line,
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
async def conn_repo(db: DatabaseConnection) -> ConnectionRepository:
    return ConnectionRepository(db)


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
        "whitelist": ["10.0.0.0/8", "192.168.1.50"],
        "cooldown_hours": 1,
    }


# ---------------------------------------------------------------------------
# parse_ss_line unit tests
# ---------------------------------------------------------------------------


def test_parse_estab_ipv4() -> None:
    line = "ESTAB   0   0   10.0.0.1:22   192.168.1.100:54321"
    result = parse_ss_line(line)
    assert result is not None
    assert result["src_ip"] == "192.168.1.100"
    assert result["dest_port"] == 22
    assert result["protocol"] == "tcp"


def test_parse_estab_ipv6() -> None:
    line = "ESTAB   0   0   [::1]:22   [2001:db8::1]:54321"
    result = parse_ss_line(line)
    assert result is not None
    assert result["src_ip"] == "2001:db8::1"
    assert result["dest_port"] == 22


def test_parse_estab_with_process_column() -> None:
    line = 'ESTAB   0   0   0.0.0.0:22   1.2.3.4:12345 users:(("sshd",pid=1234,fd=3))'
    result = parse_ss_line(line)
    assert result is not None
    assert result["src_ip"] == "1.2.3.4"
    assert result["dest_port"] == 22


def test_parse_returns_none_for_listen_state() -> None:
    line = "LISTEN  0   128   0.0.0.0:22   0.0.0.0:*"
    assert parse_ss_line(line) is None


def test_parse_returns_none_for_header_line() -> None:
    line = "State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process"
    assert parse_ss_line(line) is None


def test_parse_returns_none_for_empty_line() -> None:
    assert parse_ss_line("") is None


# ---------------------------------------------------------------------------
# is_whitelisted unit tests
# ---------------------------------------------------------------------------


def test_is_whitelisted_exact_ip_match() -> None:
    assert is_whitelisted("192.168.1.50", ["192.168.1.50"]) is True


def test_is_whitelisted_cidr_match() -> None:
    assert is_whitelisted("10.0.1.5", ["10.0.0.0/8"]) is True


def test_is_whitelisted_no_match() -> None:
    assert is_whitelisted("8.8.8.8", ["10.0.0.0/8", "192.168.1.50"]) is False


def test_is_whitelisted_empty_list() -> None:
    assert is_whitelisted("1.2.3.4", []) is False


def test_is_whitelisted_invalid_ip() -> None:
    assert is_whitelisted("not-an-ip", ["10.0.0.0/8"]) is False


def test_is_whitelisted_ignores_invalid_entry() -> None:
    assert is_whitelisted("10.0.1.1", ["not-a-cidr", "10.0.0.0/8"]) is True


def test_is_whitelisted_ipv6() -> None:
    assert is_whitelisted("2001:db8::1", ["2001:db8::/32"]) is True


# ---------------------------------------------------------------------------
# ConnectionMonitor integration tests
# ---------------------------------------------------------------------------


SS_ESTAB_UNKNOWN = "ESTAB   0   0   0.0.0.0:22   8.8.8.8:54321"
SS_ESTAB_WHITELISTED = "ESTAB   0   0   0.0.0.0:22   10.0.5.1:54321"
SS_LISTEN = "LISTEN  0   128   0.0.0.0:22   0.0.0.0:*"


@pytest.mark.asyncio
async def test_collect_fires_alert_for_unknown_ip(
    conn_repo: ConnectionRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = ConnectionMonitor(default_config, ctx, conn_repo=conn_repo)

    with patch.object(monitor, "_run_ss", return_value=[SS_ESTAB_UNKNOWN]):
        await monitor.collect()

    ctx.event_bus.publish.assert_called_once()
    event_type, payload = ctx.event_bus.publish.call_args[0]
    assert event_type == "alert.connection.unknown_ip_detected"
    assert payload["src_ip"] == "8.8.8.8"
    assert payload["dest_port"] == 22
    assert payload["protocol"] == "tcp"
    assert "timestamp" in payload


@pytest.mark.asyncio
async def test_collect_silently_ignores_whitelisted_ip(
    conn_repo: ConnectionRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = ConnectionMonitor(default_config, ctx, conn_repo=conn_repo)

    with patch.object(monitor, "_run_ss", return_value=[SS_ESTAB_WHITELISTED]):
        await monitor.collect()

    ctx.event_bus.publish.assert_not_called()


@pytest.mark.asyncio
async def test_collect_no_alert_within_cooldown(
    conn_repo: ConnectionRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = ConnectionMonitor(default_config, ctx, conn_repo=conn_repo)

    with patch.object(monitor, "_run_ss", return_value=[SS_ESTAB_UNKNOWN]):
        await monitor.collect()  # first time → alert
        await monitor.collect()  # within cooldown → no alert

    assert ctx.event_bus.publish.call_count == 1


@pytest.mark.asyncio
async def test_collect_re_alerts_after_cooldown_expires(
    conn_repo: ConnectionRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = ConnectionMonitor(default_config, ctx, conn_repo=conn_repo)

    past = datetime.now(UTC) - timedelta(hours=2)
    await conn_repo.upsert("8.8.8.8", 22, "tcp", past)

    with patch.object(monitor, "_run_ss", return_value=[SS_ESTAB_UNKNOWN]):
        await monitor.collect()

    ctx.event_bus.publish.assert_called_once()


@pytest.mark.asyncio
async def test_collect_deduplicates_same_connection_in_single_poll(
    conn_repo: ConnectionRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = ConnectionMonitor(default_config, ctx, conn_repo=conn_repo)

    with patch.object(monitor, "_run_ss", return_value=[SS_ESTAB_UNKNOWN, SS_ESTAB_UNKNOWN]):
        await monitor.collect()

    assert ctx.event_bus.publish.call_count == 1


@pytest.mark.asyncio
async def test_collect_ignores_listen_lines(
    conn_repo: ConnectionRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = ConnectionMonitor(default_config, ctx, conn_repo=conn_repo)

    with patch.object(monitor, "_run_ss", return_value=[SS_LISTEN]):
        await monitor.collect()

    ctx.event_bus.publish.assert_not_called()


@pytest.mark.asyncio
async def test_collect_logs_warning_when_no_whitelist_configured(
    conn_repo: ConnectionRepository,
) -> None:
    config = {"enabled": True, "cooldown_hours": 1}  # no whitelist
    ctx = _make_ctx()
    monitor = ConnectionMonitor(config, ctx, conn_repo=conn_repo)

    with (
        patch.object(monitor, "_run_ss", return_value=[]),
        patch.object(monitor.logger, "warning") as mock_warn,
    ):
        await monitor.collect()
        mock_warn.assert_called_once()
        assert "whitelist" in mock_warn.call_args[0][0].lower()


@pytest.mark.asyncio
async def test_collect_startup_warning_logged_only_once(
    conn_repo: ConnectionRepository,
) -> None:
    config = {"enabled": True, "cooldown_hours": 1}
    ctx = _make_ctx()
    monitor = ConnectionMonitor(config, ctx, conn_repo=conn_repo)

    with (
        patch.object(monitor, "_run_ss", return_value=[]),
        patch.object(monitor.logger, "warning") as mock_warn,
    ):
        await monitor.collect()
        await monitor.collect()
        assert mock_warn.call_count == 1


@pytest.mark.asyncio
async def test_collect_handles_ss_failure_gracefully(
    conn_repo: ConnectionRepository, default_config: dict
) -> None:
    ctx = _make_ctx()
    monitor = ConnectionMonitor(default_config, ctx, conn_repo=conn_repo)

    with patch.object(monitor, "_run_ss", side_effect=RuntimeError("ss not found")):
        await monitor.collect()  # must not raise

    ctx.event_bus.publish.assert_not_called()
