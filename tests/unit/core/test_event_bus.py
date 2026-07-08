from __future__ import annotations

import pytest

from system_sentinel.core.event_bus import InProcessEventBus


@pytest.mark.asyncio
async def test_subscribe_and_receive_event() -> None:
    bus = InProcessEventBus()
    received: list[tuple[str, object]] = []

    async def handler(event_type: str, payload: object) -> None:
        received.append((event_type, payload))

    bus.subscribe("test.event", handler)
    await bus.publish("test.event", {"key": "value"})

    assert len(received) == 1
    assert received[0] == ("test.event", {"key": "value"})


@pytest.mark.asyncio
async def test_unsubscribed_event_not_received() -> None:
    bus = InProcessEventBus()
    received: list[object] = []

    async def handler(event_type: str, payload: object) -> None:
        received.append(payload)

    bus.subscribe("other.event", handler)
    await bus.publish("test.event", "hello")

    assert received == []


@pytest.mark.asyncio
async def test_multiple_subscribers_all_called() -> None:
    bus = InProcessEventBus()
    calls: list[str] = []

    async def h1(event_type: str, payload: object) -> None:
        calls.append("h1")

    async def h2(event_type: str, payload: object) -> None:
        calls.append("h2")

    bus.subscribe("evt", h1)
    bus.subscribe("evt", h2)
    await bus.publish("evt", None)

    assert calls == ["h1", "h2"]


@pytest.mark.asyncio
async def test_failing_handler_does_not_prevent_others() -> None:
    bus = InProcessEventBus()
    reached: list[str] = []

    async def bad_handler(event_type: str, payload: object) -> None:
        raise RuntimeError("oops")

    async def good_handler(event_type: str, payload: object) -> None:
        reached.append("good")

    bus.subscribe("evt", bad_handler)
    bus.subscribe("evt", good_handler)
    await bus.publish("evt", None)  # must not raise

    assert reached == ["good"]


@pytest.mark.asyncio
async def test_publish_with_no_subscribers_is_safe() -> None:
    bus = InProcessEventBus()
    await bus.publish("ghost.event", {})  # must not raise
