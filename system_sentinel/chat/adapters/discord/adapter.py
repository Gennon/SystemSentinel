from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.base import (
    AlertSeverity,
    BaseChatAdapter,
    InboundMessage,
    OutboundMessage,
)

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext

try:
    import discord as _discord  # type: ignore[import-not-found]

    HAS_DISCORD = True
except ImportError:
    HAS_DISCORD = False

# Severity → Discord embed colour (RGB hex)
_SEVERITY_COLOUR: dict[AlertSeverity, int] = {
    AlertSeverity.INFO: 0x3498DB,  # blue
    AlertSeverity.WARNING: 0xF1C40F,  # yellow
    AlertSeverity.CRITICAL: 0xE74C3C,  # red
}


class DiscordAdapter(BaseChatAdapter):
    """Chat adapter that sends and receives messages via a Discord bot."""

    name = "discord"

    def __init__(self, config: dict[str, Any], app_ctx: AppContext) -> None:
        super().__init__(config, app_ctx)
        if not HAS_DISCORD:
            raise ImportError(
                "discord.py is required for the Discord adapter. "
                "Install it with: pip install 'system-sentinel[discord]'"
            )
        self._token: str = config["token"]
        self._default_channel_id: int = int(config["channel_id"])

        intents = _discord.Intents.default()
        intents.message_content = True
        self._client: _discord.Client = _discord.Client(intents=intents)
        self._ready = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

        @self._client.event  # type: ignore[untyped-decorator]
        async def on_ready() -> None:
            self.logger.info("Discord bot connected as %s", self._client.user)
            self._ready.set()

        @self._client.event  # type: ignore[untyped-decorator]
        async def on_message(message: _discord.Message) -> None:
            if message.author == self._client.user:
                return
            if self._message_handler is None:
                return
            inbound = InboundMessage(
                adapter=self.name,
                channel_id=str(message.channel.id),
                user_id=str(message.author.id),
                username=str(message.author),
                text=message.content,
                raw=message,
                received_at=datetime.now(UTC),
            )
            args = message.content.split()
            try:
                await self._message_handler(inbound, args)
            except Exception:
                self.logger.exception("Error in message handler")

    async def start(self) -> None:
        """Connect the Discord bot and wait until it is ready."""
        self._task = asyncio.create_task(self._client.start(self._token))
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=30.0)
        except TimeoutError:
            self.logger.warning("Discord bot did not become ready within 30 seconds")

    async def stop(self) -> None:
        """Disconnect the Discord bot cleanly."""
        await self._client.close()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task

    async def send(self, channel_id: str, message: OutboundMessage) -> None:
        """Send *message* to the specified channel ID."""
        await self._ready.wait()
        channel = self._client.get_channel(int(channel_id))
        if channel is None:
            # Fall back to an API fetch if the channel is not in cache
            try:
                channel = await self._client.fetch_channel(int(channel_id))
            except Exception:
                self.logger.error("Channel %s not found or not accessible", channel_id)
                return
        embed = self._build_embed(message)
        await channel.send(embed=embed)

    async def send_to_default(self, message: OutboundMessage) -> None:
        """Send *message* to the configured default alert channel."""
        await self.send(str(self._default_channel_id), message)

    def _build_embed(self, message: OutboundMessage) -> _discord.Embed:
        colour = _SEVERITY_COLOUR.get(message.severity, 0x95A5A6)
        embed = _discord.Embed(
            title=message.title,
            description=message.text,
            colour=colour,
        )
        if message.fields:
            for name, value in message.fields.items():
                embed.add_field(name=name, value=value, inline=False)
        return embed
