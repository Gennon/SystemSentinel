from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest

from system_sentinel.chat.base import AlertSeverity, BaseChatAdapter, OutboundMessage
from system_sentinel.chat.router import ChatRouter
from system_sentinel.core.context import AppContext

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx() -> AppContext:
    return AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )


class _RecordingAdapter(BaseChatAdapter):
    name = "recording"

    def __init__(self, adapter_name: str = "recording") -> None:
        # Bypass BaseChatAdapter.__init__ — we don't need a real ctx here
        self.name = adapter_name  # type: ignore[misc]
        self._message_handler = None
        self.logger = logging.getLogger(f"test.{adapter_name}")
        self.sent: list[tuple[str, OutboundMessage]] = []
        self.default_sent: list[OutboundMessage] = []

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def send(self, channel_id: str, message: OutboundMessage) -> None:
        self.sent.append((channel_id, message))

    async def send_to_default(self, message: OutboundMessage) -> None:
        self.default_sent.append(message)


# ---------------------------------------------------------------------------
# register()
# ---------------------------------------------------------------------------


def test_register_adds_adapter() -> None:
    router = ChatRouter()
    adapter = _RecordingAdapter()
    router.register(adapter)
    assert adapter in router.adapters


def test_register_multiple_adapters() -> None:
    router = ChatRouter()
    a1, a2 = _RecordingAdapter("a1"), _RecordingAdapter("a2")
    router.register(a1)
    router.register(a2)
    assert len(router.adapters) == 2


# ---------------------------------------------------------------------------
# broadcast()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_reaches_all_adapters() -> None:
    router = ChatRouter()
    a1, a2 = _RecordingAdapter("a1"), _RecordingAdapter("a2")
    router.register(a1)
    router.register(a2)
    msg = OutboundMessage(text="alert", severity=AlertSeverity.CRITICAL)

    await router.broadcast(msg)

    assert a1.default_sent == [msg]
    assert a2.default_sent == [msg]


@pytest.mark.asyncio
async def test_broadcast_continues_after_adapter_error() -> None:
    """A failing adapter must not prevent other adapters from receiving the message."""
    router = ChatRouter()
    bad = _RecordingAdapter("bad")
    good = _RecordingAdapter("good")

    async def _raise(message: OutboundMessage) -> None:
        raise RuntimeError("network error")

    bad.send_to_default = _raise  # type: ignore[method-assign]
    router.register(bad)
    router.register(good)

    msg = OutboundMessage(text="alert")
    await router.broadcast(msg)  # must not raise

    assert good.default_sent == [msg]


# ---------------------------------------------------------------------------
# send() — targeted delivery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_delivers_to_correct_adapter() -> None:
    router = ChatRouter()
    a1 = _RecordingAdapter("alpha")
    a2 = _RecordingAdapter("beta")
    router.register(a1)
    router.register(a2)

    msg = OutboundMessage(text="targeted")
    await router.send("beta", "777", msg)

    assert a2.sent == [("777", msg)]
    assert a1.sent == []


@pytest.mark.asyncio
async def test_send_raises_for_unknown_adapter() -> None:
    router = ChatRouter()
    with pytest.raises(KeyError, match="missing"):
        await router.send("missing", "000", OutboundMessage(text="x"))


# ---------------------------------------------------------------------------
# adapters property returns a copy
# ---------------------------------------------------------------------------


def test_adapters_property_is_a_copy() -> None:
    router = ChatRouter()
    adapter = _RecordingAdapter()
    router.register(adapter)

    copy = router.adapters
    copy.clear()

    assert len(router.adapters) == 1
