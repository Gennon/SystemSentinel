from __future__ import annotations

import asyncio
import logging
import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.core.context import AppContext

# ---------------------------------------------------------------------------
# Build a minimal discord stub so the adapter can be imported without
# discord.py installed.
# ---------------------------------------------------------------------------


def _build_discord_stub() -> types.ModuleType:
    """Create a minimal mock of the `discord` package."""
    mod = types.ModuleType("discord")

    class Intents:
        def __init__(self) -> None:
            self.message_content: bool = False

        @classmethod
        def default(cls) -> Intents:
            return cls()

    class Embed:
        def __init__(
            self,
            *,
            title: str | None = None,
            description: str | None = None,
            colour: int = 0,
        ) -> None:
            self.title = title
            self.description = description
            self.colour = colour
            self.fields: list[dict[str, Any]] = []

        def add_field(self, *, name: str, value: str, inline: bool = True) -> None:
            self.fields.append({"name": name, "value": value, "inline": inline})

    class _FakeChannel:
        def __init__(self, channel_id: int) -> None:
            self.id = channel_id
            self.send = AsyncMock()

    class Client:
        def __init__(self, *, intents: Intents | None = None) -> None:
            self.user: object = "TestBot#0000"
            self._channels: dict[int, _FakeChannel] = {}
            self._event_handlers: dict[str, Any] = {}

        def event(self, coro: Any) -> Any:
            self._event_handlers[coro.__name__] = coro
            return coro

        def get_channel(self, channel_id: int) -> _FakeChannel | None:
            return self._channels.get(channel_id)

        async def fetch_channel(self, channel_id: int) -> _FakeChannel:
            ch = _FakeChannel(channel_id)
            self._channels[channel_id] = ch
            return ch

        async def start(self, token: str) -> None:
            # Immediately invoke on_ready so the adapter's _ready event is set
            on_ready = self._event_handlers.get("on_ready")
            if on_ready is not None:
                await on_ready()
            # Block until closed
            await asyncio.sleep(9999)

        async def close(self) -> None:
            pass

    mod.Intents = Intents  # type: ignore[attr-defined]
    mod.Embed = Embed  # type: ignore[attr-defined]
    mod.Client = Client  # type: ignore[attr-defined]
    # Minimal stubs so type annotations in the adapter don't break at import
    mod.Message = MagicMock  # type: ignore[attr-defined]
    return mod


# Install the stub *before* importing the adapter so HAS_DISCORD = True
_DISCORD_STUB = _build_discord_stub()
sys.modules.setdefault("discord", _DISCORD_STUB)


# Now import the adapter — it will pick up our stub
from system_sentinel.chat.adapters.discord.adapter import (  # noqa: E402
    _SEVERITY_COLOUR,
    DiscordAdapter,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx() -> AppContext:
    return AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )


def _make_adapter(config: dict[str, Any] | None = None) -> DiscordAdapter:
    cfg: dict[str, Any] = {
        "token": "fake-token",
        "channel_id": "123456789",
        "enabled": True,
    }
    if config:
        cfg.update(config)
    return DiscordAdapter(cfg, _make_ctx())


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------


def test_adapter_name_is_discord() -> None:
    assert DiscordAdapter.name == "discord"


def test_adapter_stores_default_channel_id() -> None:
    adapter = _make_adapter({"channel_id": "999"})
    assert adapter._default_channel_id == 999


def test_missing_discord_raises_import_error() -> None:
    """If discord.py is absent, constructing DiscordAdapter must raise ImportError."""
    with (
        patch("system_sentinel.chat.adapters.discord.adapter.HAS_DISCORD", False),
        pytest.raises(ImportError, match=r"discord\.py is required"),
    ):
        _make_adapter()


# ---------------------------------------------------------------------------
# start() / stop()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_sets_ready_event() -> None:
    adapter = _make_adapter()
    await adapter.start()
    assert adapter._ready.is_set()
    await adapter.stop()


@pytest.mark.asyncio
async def test_stop_cancels_background_task() -> None:
    adapter = _make_adapter()
    await adapter.start()
    assert adapter._task is not None
    await adapter.stop()
    assert adapter._task.cancelled() or adapter._task.done()


# ---------------------------------------------------------------------------
# send() / send_to_default()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_to_default_uses_configured_channel() -> None:
    adapter = _make_adapter({"channel_id": "111"})
    await adapter.start()

    msg = OutboundMessage(text="hello world")
    await adapter.send_to_default(msg)

    # The stub's fetch_channel will have created and stored a channel
    channel = adapter._client._channels.get(111)
    assert channel is not None
    channel.send.assert_awaited_once()

    await adapter.stop()


@pytest.mark.asyncio
async def test_send_uses_channel_from_get_channel_if_cached() -> None:
    adapter = _make_adapter({"channel_id": "222"})
    await adapter.start()

    # Pre-populate the channel cache with a mock channel
    fake_channel = MagicMock()
    fake_channel.id = 222
    fake_channel.send = AsyncMock()
    adapter._client._channels[222] = fake_channel  # type: ignore[union-attr]

    msg = OutboundMessage(text="cached")
    await adapter.send("222", msg)

    fake_channel.send.assert_awaited_once()
    await adapter.stop()


@pytest.mark.asyncio
async def test_send_logs_error_when_channel_unreachable() -> None:
    adapter = _make_adapter({"channel_id": "333"})
    await adapter.start()

    async def _fail(channel_id: int) -> None:
        raise Exception("forbidden")

    adapter._client.fetch_channel = _fail  # type: ignore[method-assign]

    # Must not raise — just log the error
    msg = OutboundMessage(text="no channel")
    await adapter.send("333", msg)

    await adapter.stop()


@pytest.mark.asyncio
async def test_send_splits_large_message_across_multiple_embeds() -> None:
    adapter = _make_adapter({"channel_id": "334"})
    await adapter.start()

    long_text = "x" * 9000
    msg = OutboundMessage(text=long_text, title="Storage Report")
    await adapter.send("334", msg)

    channel = adapter._client._channels.get(334)
    assert channel is not None
    assert channel.send.await_count == 3
    await adapter.stop()


# ---------------------------------------------------------------------------
# _build_embed() — severity → colour mapping
# ---------------------------------------------------------------------------


def test_build_embed_info_colour() -> None:
    adapter = _make_adapter()
    embed = adapter._build_embed(OutboundMessage(text="x", severity=AlertSeverity.INFO))
    assert embed.colour == _SEVERITY_COLOUR[AlertSeverity.INFO]


def test_build_embed_warning_colour() -> None:
    adapter = _make_adapter()
    embed = adapter._build_embed(OutboundMessage(text="x", severity=AlertSeverity.WARNING))
    assert embed.colour == _SEVERITY_COLOUR[AlertSeverity.WARNING]


def test_build_embed_critical_colour() -> None:
    adapter = _make_adapter()
    embed = adapter._build_embed(OutboundMessage(text="x", severity=AlertSeverity.CRITICAL))
    assert embed.colour == _SEVERITY_COLOUR[AlertSeverity.CRITICAL]


def test_build_embed_sets_title_and_description() -> None:
    adapter = _make_adapter()
    embed = adapter._build_embed(OutboundMessage(text="body text", title="My Title"))
    assert embed.title == "My Title"
    assert embed.description == "body text"


def test_build_embed_adds_fields() -> None:
    adapter = _make_adapter()
    embed = adapter._build_embed(
        OutboundMessage(
            text="disk full",
            fields={"Volume": "/dev/sda1", "Usage": "98%"},
        )
    )
    field_names = [f["name"] for f in embed.fields]
    assert "Volume" in field_names
    assert "Usage" in field_names


def test_build_embed_no_fields_when_none() -> None:
    adapter = _make_adapter()
    embed = adapter._build_embed(OutboundMessage(text="plain"))
    assert embed.fields == []


def test_build_embed_truncates_description_to_discord_limit() -> None:
    adapter = _make_adapter()
    embed = adapter._build_embed(OutboundMessage(text="x" * 5000))
    assert embed.description is not None
    assert len(embed.description) == 4096


def test_build_embed_limits_number_of_fields() -> None:
    adapter = _make_adapter()
    fields = {f"key-{i}": "value" for i in range(30)}
    embed = adapter._build_embed(OutboundMessage(text="body", fields=fields))
    assert len(embed.fields) == 25


@pytest.mark.asyncio
async def test_on_message_sends_handler_reply_to_channel() -> None:
    adapter = _make_adapter()
    await adapter.start()

    async def _handler(message, args):  # type: ignore[no-untyped-def]
        return OutboundMessage(text=f"ack {args[0]}")

    adapter.on_message(_handler)

    channel = await adapter._client.fetch_channel(444)
    message = MagicMock()
    message.author = MagicMock()
    message.author.id = 12345
    message.author.__str__.return_value = "tester#0001"
    message.channel = channel
    message.content = "!status"
    on_message = adapter._client._event_handlers["on_message"]

    await on_message(message)

    channel.send.assert_awaited_once()
    sent_embed = channel.send.call_args.kwargs["embed"]
    assert sent_embed.description == "ack !status"
    await adapter.stop()


@pytest.mark.asyncio
async def test_on_message_sends_thinking_message_before_slow_reply() -> None:
    adapter = _make_adapter()
    await adapter.start()

    async def _handler(_message, _args):  # type: ignore[no-untyped-def]
        await asyncio.sleep(0.02)
        return OutboundMessage(text="final answer")

    adapter.on_message(_handler)

    channel = await adapter._client.fetch_channel(445)
    message = MagicMock()
    message.author = MagicMock()
    message.author.id = 12345
    message.author.__str__.return_value = "tester#0001"
    message.channel = channel
    message.content = "!ask why is cpu high?"
    on_message = adapter._client._event_handlers["on_message"]

    with patch(
        "system_sentinel.chat.adapters.discord.adapter._COMMAND_RESPONSE_TIMEOUT_SECONDS",
        0.001,
        create=True,
    ):
        await on_message(message)

    assert channel.send.await_count == 2
    first_embed = channel.send.await_args_list[0].kwargs["embed"]
    second_embed = channel.send.await_args_list[1].kwargs["embed"]
    assert first_embed.description is not None
    assert first_embed.description.lower().startswith("thinking")
    assert second_embed.description == "final answer"
    await adapter.stop()


@pytest.mark.asyncio
async def test_on_reaction_sends_handler_reply_to_channel() -> None:
    adapter = _make_adapter()
    await adapter.start()

    async def _handler(_reaction):  # type: ignore[no-untyped-def]
        return OutboundMessage(text="confirmed")

    adapter.on_reaction(_handler)

    channel = await adapter._client.fetch_channel(555)
    user = MagicMock()
    user.id = 54321
    user.__str__.return_value = "tester#0002"

    reaction = MagicMock()
    reaction.emoji = "✅"
    reaction.message.channel = channel

    on_reaction_add = adapter._client._event_handlers["on_reaction_add"]
    await on_reaction_add(reaction, user)

    channel.send.assert_awaited_once()
    sent_embed = channel.send.call_args.kwargs["embed"]
    assert sent_embed.description == "confirmed"
    await adapter.stop()
