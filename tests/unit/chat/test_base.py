from __future__ import annotations

from datetime import UTC, datetime

import pytest

from system_sentinel.chat.base import (
    AlertSeverity,
    BaseChatAdapter,
    InboundMessage,
    OutboundMessage,
)

# ---------------------------------------------------------------------------
# AlertSeverity
# ---------------------------------------------------------------------------


def test_alert_severity_values() -> None:
    assert AlertSeverity.INFO == "info"
    assert AlertSeverity.WARNING == "warning"
    assert AlertSeverity.CRITICAL == "critical"


# ---------------------------------------------------------------------------
# OutboundMessage defaults
# ---------------------------------------------------------------------------


def test_outbound_message_defaults() -> None:
    msg = OutboundMessage(text="hello")
    assert msg.severity == AlertSeverity.INFO
    assert msg.title is None
    assert msg.fields is None
    assert msg.reply_to is None


def test_outbound_message_with_all_fields() -> None:
    msg = OutboundMessage(
        text="disk full",
        title="Disk Alert",
        severity=AlertSeverity.CRITICAL,
        fields={"volume": "/dev/sda1", "usage": "98%"},
    )
    assert msg.severity == AlertSeverity.CRITICAL
    assert msg.title == "Disk Alert"
    assert msg.fields == {"volume": "/dev/sda1", "usage": "98%"}


# ---------------------------------------------------------------------------
# InboundMessage
# ---------------------------------------------------------------------------


def test_inbound_message_fields() -> None:
    now = datetime.now(UTC)
    msg = InboundMessage(
        adapter="discord",
        channel_id="123",
        user_id="456",
        username="alice",
        text="!status",
        raw=object(),
        received_at=now,
    )
    assert msg.adapter == "discord"
    assert msg.text == "!status"
    assert msg.received_at is now


# ---------------------------------------------------------------------------
# BaseChatAdapter — concrete stub for testing abstract interface
# ---------------------------------------------------------------------------


class _StubAdapter(BaseChatAdapter):
    name = "stub"
    started = False
    stopped = False
    sent: list[tuple[str, OutboundMessage]]
    default_sent: list[OutboundMessage]

    def __init__(self, config: dict, app_ctx: object) -> None:  # type: ignore[override]
        super().__init__(config, app_ctx)  # type: ignore[arg-type]
        self.sent = []
        self.default_sent = []

    async def start(self) -> None:
        _StubAdapter.started = True

    async def stop(self) -> None:
        _StubAdapter.stopped = True

    async def send(self, channel_id: str, message: OutboundMessage) -> None:
        self.sent.append((channel_id, message))

    async def send_to_default(self, message: OutboundMessage) -> None:
        self.default_sent.append(message)


def _make_stub(config: dict | None = None) -> _StubAdapter:
    import logging
    from unittest.mock import AsyncMock

    from system_sentinel.core.context import AppContext

    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    return _StubAdapter(config or {}, ctx)


def test_adapter_logger_name_includes_adapter_name() -> None:
    stub = _make_stub()
    assert stub.logger.name.endswith("stub")


def test_on_message_registers_handler() -> None:
    stub = _make_stub()

    async def handler(msg: InboundMessage, args: list[str]) -> OutboundMessage | None:
        return None

    stub.on_message(handler)
    assert stub._message_handler is handler


@pytest.mark.asyncio
async def test_stub_send_records_messages() -> None:
    stub = _make_stub()
    msg = OutboundMessage(text="test", severity=AlertSeverity.WARNING)
    await stub.send("999", msg)
    assert stub.sent == [("999", msg)]


@pytest.mark.asyncio
async def test_stub_send_to_default_records_messages() -> None:
    stub = _make_stub()
    msg = OutboundMessage(text="default test")
    await stub.send_to_default(msg)
    assert stub.default_sent == [msg]
