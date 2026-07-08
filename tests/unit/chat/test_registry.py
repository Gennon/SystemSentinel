from __future__ import annotations

from importlib.metadata import EntryPoint
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from system_sentinel.chat.base import BaseChatAdapter, OutboundMessage
from system_sentinel.chat.registry import ChatRegistry
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


class _FakeAdapter(BaseChatAdapter):
    name = "fake"

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def send(self, channel_id: str, message: OutboundMessage) -> None: ...

    async def send_to_default(self, message: OutboundMessage) -> None: ...


def _make_entry_point(name: str, cls: type) -> MagicMock:
    ep = MagicMock(spec=EntryPoint)
    ep.name = name
    ep.load.return_value = cls
    return ep


def _make_registry(config: dict[str, Any]) -> ChatRegistry:
    return ChatRegistry(config, _make_ctx())


# ---------------------------------------------------------------------------
# discover() — only loads adapters with enabled=True
# ---------------------------------------------------------------------------


def test_discover_loads_enabled_adapter() -> None:
    registry = _make_registry({"fake": {"enabled": True}})

    with patch(
        "system_sentinel.chat.registry.entry_points",
        return_value=[_make_entry_point("fake", _FakeAdapter)],
    ):
        registry.discover()

    assert "fake" in registry.adapters
    assert isinstance(registry.adapters["fake"], _FakeAdapter)


def test_discover_skips_disabled_adapter() -> None:
    registry = _make_registry({"fake": {"enabled": False}})

    with patch(
        "system_sentinel.chat.registry.entry_points",
        return_value=[_make_entry_point("fake", _FakeAdapter)],
    ):
        registry.discover()

    assert "fake" not in registry.adapters


def test_discover_skips_adapter_with_no_config() -> None:
    """Adapters without any config entry are treated as disabled."""
    registry = _make_registry({})

    with patch(
        "system_sentinel.chat.registry.entry_points",
        return_value=[_make_entry_point("fake", _FakeAdapter)],
    ):
        registry.discover()

    assert "fake" not in registry.adapters


def test_discover_handles_load_error_gracefully() -> None:
    """A broken entry point must not crash the registry — it logs and continues."""
    registry = _make_registry({"bad": {"enabled": True}})
    bad_ep = MagicMock(spec=EntryPoint)
    bad_ep.name = "bad"
    bad_ep.load.side_effect = ImportError("missing dep")

    with patch(
        "system_sentinel.chat.registry.entry_points",
        return_value=[bad_ep],
    ):
        registry.discover()  # should not raise

    assert "bad" not in registry.adapters


def test_discover_loads_multiple_adapters() -> None:
    registry = _make_registry({"fake": {"enabled": True}, "other": {"enabled": True}})

    class _OtherAdapter(_FakeAdapter):
        name = "other"

    with patch(
        "system_sentinel.chat.registry.entry_points",
        return_value=[
            _make_entry_point("fake", _FakeAdapter),
            _make_entry_point("other", _OtherAdapter),
        ],
    ):
        registry.discover()

    assert set(registry.adapters.keys()) == {"fake", "other"}


def test_adapters_property_returns_copy() -> None:
    """Mutations to the returned dict must not affect the registry's state."""
    registry = _make_registry({"fake": {"enabled": True}})

    with patch(
        "system_sentinel.chat.registry.entry_points",
        return_value=[_make_entry_point("fake", _FakeAdapter)],
    ):
        registry.discover()

    copy = registry.adapters
    copy["injected"] = MagicMock()  # type: ignore[assignment]
    assert "injected" not in registry.adapters
