from __future__ import annotations

import logging

import pytest

from system_sentinel.alerts.handler import (
    AlertHandler,
    _format_brute_force,
    _format_connection_daily_digest,
    _format_connection_repeat_threshold,
    _format_unknown_connection,
)
from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.chat.router import ChatRouter
from system_sentinel.core.event_bus import InProcessEventBus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_router() -> tuple[ChatRouter, list[OutboundMessage]]:
    """Return a ChatRouter wired to a recording adapter."""
    router = ChatRouter()
    broadcast_calls: list[OutboundMessage] = []

    class _RecordingAdapter:
        name = "recording"
        logger = logging.getLogger("test.recording")

        async def send_to_default(self, message: OutboundMessage) -> None:
            broadcast_calls.append(message)

        async def start(self) -> None: ...

        async def stop(self) -> None: ...

        async def send(self, channel_id: str, message: OutboundMessage) -> None: ...

    router.register(_RecordingAdapter())  # type: ignore[arg-type]
    return router, broadcast_calls


_UNKNOWN_CONNECTION_PAYLOAD = {
    "src_ip": "8.8.8.8",
    "dest_port": 22,
    "protocol": "tcp",
    "timestamp": "2024-01-01T00:00:00+00:00",
}


# ---------------------------------------------------------------------------
# _format_unknown_connection unit tests
# ---------------------------------------------------------------------------


def test_format_unknown_connection_title() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert "Unknown" in (msg.title or "")


def test_format_unknown_connection_severity_is_warning() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING


def test_format_unknown_connection_includes_src_ip() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert "8.8.8.8" in msg.text


def test_format_unknown_connection_includes_port_and_protocol() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert "22" in msg.text
    assert "tcp" in msg.text


def test_format_unknown_connection_fields_populated() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert msg.fields is not None
    assert msg.fields["Source IP"] == "8.8.8.8"
    assert msg.fields["Destination Port"] == "22"


# ---------------------------------------------------------------------------
# AlertHandler integration tests — unknown connection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handler_broadcasts_on_unknown_connection_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.unknown_ip_detected", _UNKNOWN_CONNECTION_PAYLOAD)

    assert len(calls) == 1
    assert "8.8.8.8" in calls[0].text


@pytest.mark.asyncio
async def test_handler_unknown_connection_message_severity_is_warning() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.unknown_ip_detected", _UNKNOWN_CONNECTION_PAYLOAD)

    assert calls[0].severity == AlertSeverity.WARNING


_BRUTE_FORCE_PAYLOAD = {
    "ip_address": "1.2.3.4",
    "attempt_count": 7,
    "usernames": ["root", "admin", "ubuntu"],
    "window_minutes": 10,
}

_CONNECTION_REPEAT_PAYLOAD = {
    "src_ip": "8.8.8.8",
    "attempt_count": 4,
    "window_minutes": 10,
    "ports": [22, 80],
    "timestamp": "2024-01-01T00:00:00+00:00",
}

_CONNECTION_DAILY_DIGEST_PAYLOAD = {
    "timestamp": "2024-01-01T08:00:00+00:00",
    "period_hours": 24,
    "rows": [
        {"ip_address": "8.8.8.8", "dest_port": 22, "attempts": 3},
        {"ip_address": "1.2.3.4", "dest_port": 80, "attempts": 2},
    ],
}


# ---------------------------------------------------------------------------
# _format_brute_force unit tests
# ---------------------------------------------------------------------------


def test_format_brute_force_title() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert "Brute Force" in (msg.title or "")


def test_format_brute_force_severity_is_critical() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert msg.severity == AlertSeverity.CRITICAL


def test_format_brute_force_includes_ip() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert "1.2.3.4" in msg.text


def test_format_brute_force_includes_attempt_count() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert "7" in msg.text


def test_format_brute_force_includes_all_usernames() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    for username in ["root", "admin", "ubuntu"]:
        assert username in msg.text


def test_format_brute_force_fields_populated() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert msg.fields is not None
    assert msg.fields["IP Address"] == "1.2.3.4"
    assert msg.fields["Attempts"] == "7"


# ---------------------------------------------------------------------------
# AlertHandler integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handler_broadcasts_on_brute_force_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.brute_force_detected", _BRUTE_FORCE_PAYLOAD)

    assert len(calls) == 1
    assert "1.2.3.4" in calls[0].text


@pytest.mark.asyncio
async def test_handler_does_not_broadcast_for_unrelated_events() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("metrics.cpu.high", {"value": 99})

    assert calls == []


@pytest.mark.asyncio
async def test_handler_message_includes_usernames() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.brute_force_detected", _BRUTE_FORCE_PAYLOAD)

    msg = calls[0]
    assert "root" in msg.text
    assert "admin" in msg.text


@pytest.mark.asyncio
async def test_handler_message_severity_is_critical() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.brute_force_detected", _BRUTE_FORCE_PAYLOAD)

    assert calls[0].severity == AlertSeverity.CRITICAL


def test_format_connection_repeat_threshold_severity_is_critical() -> None:
    msg = _format_connection_repeat_threshold(_CONNECTION_REPEAT_PAYLOAD)
    assert msg.severity == AlertSeverity.CRITICAL


def test_format_connection_repeat_threshold_includes_ports() -> None:
    msg = _format_connection_repeat_threshold(_CONNECTION_REPEAT_PAYLOAD)
    assert "22" in msg.text
    assert "80" in msg.text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_connection_repeat_threshold_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.repeated_attempts_detected", _CONNECTION_REPEAT_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL
    assert "8.8.8.8" in calls[0].text


def test_format_connection_daily_digest_fields() -> None:
    msg = _format_connection_daily_digest(_CONNECTION_DAILY_DIGEST_PAYLOAD)
    assert msg.fields is not None
    assert msg.fields["Unique IPs"] == "2"
    assert msg.fields["Unique Ports"] == "2"
    assert msg.fields["Total Attempts"] == "5"


@pytest.mark.asyncio
async def test_handler_broadcasts_on_connection_daily_digest_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.daily_digest", _CONNECTION_DAILY_DIGEST_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING
    assert "8.8.8.8" in calls[0].text
