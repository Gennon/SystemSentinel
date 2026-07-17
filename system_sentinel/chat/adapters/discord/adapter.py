from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from io import BytesIO
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.base import (
    AlertSeverity,
    BaseChatAdapter,
    InboundMessage,
    InboundReaction,
    OutboundAttachment,
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

# Discord embed hard limits.
_EMBED_TITLE_MAX = 256
_EMBED_DESCRIPTION_MAX = 4096
_EMBED_FIELD_NAME_MAX = 256
_EMBED_FIELD_VALUE_MAX = 1024
_EMBED_FIELDS_MAX = 25
_EMBED_TOTAL_CHARS_MAX = 6000
_COMMAND_RESPONSE_TIMEOUT_SECONDS = 30.0
_CODE_FENCE_CHUNK_OVERHEAD = 16


def _truncate(value: str | None, max_len: int) -> str | None:
    if value is None or len(value) <= max_len:
        return value
    if max_len <= 1:
        return value[:max_len]
    return f"{value[: max_len - 1]}…"


def _split_for_embed_descriptions(text: str, chunk_size: int) -> list[str]:
    if len(text) <= chunk_size:
        return [text]
    safe_chunk_size = max(1, chunk_size - _CODE_FENCE_CHUNK_OVERHEAD)
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(line) > safe_chunk_size:
            if current:
                chunks.append(current)
                current = ""
            for idx in range(0, len(line), safe_chunk_size):
                chunks.append(line[idx : idx + safe_chunk_size])
            continue
        if len(current) + len(line) > safe_chunk_size:
            chunks.append(current)
            current = line
        else:
            current += line
    if current:
        chunks.append(current)

    # Keep markdown code fences balanced for each embed description.
    balanced_chunks: list[str] = []
    carry_fence_marker: str | None = None
    for chunk in chunks:
        fence_marker = carry_fence_marker
        balanced = f"{fence_marker}\n{chunk}" if fence_marker is not None else chunk

        for line in chunk.splitlines():
            marker = line.strip()
            if marker.startswith("```"):
                if fence_marker is None:
                    fence_marker = marker if len(marker) > 3 else "```"
                else:
                    fence_marker = None

        if fence_marker is not None:
            balanced = f"{balanced}\n```"
            carry_fence_marker = fence_marker
        else:
            carry_fence_marker = None

        balanced_chunks.append(balanced)

    return balanced_chunks


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
                response_future: asyncio.Future[OutboundMessage | None] = asyncio.ensure_future(
                    self._message_handler(inbound, args)
                )
                try:
                    response = await asyncio.wait_for(
                        asyncio.shield(response_future),
                        timeout=_COMMAND_RESPONSE_TIMEOUT_SECONDS,
                    )
                except TimeoutError:
                    await self.send(
                        str(message.channel.id),
                        OutboundMessage(
                            text="Thinking... still working on that. I'll reply shortly.",
                            reply_to=inbound,
                        ),
                    )
                    response = await response_future
                if response is not None:
                    await self.send(str(message.channel.id), response)
            except Exception:
                self.logger.exception("Error in message handler")

        @self._client.event  # type: ignore[untyped-decorator]
        async def on_reaction_add(reaction: Any, user: Any) -> None:
            if user == self._client.user:
                return
            if self._reaction_handler is None:
                return
            inbound = InboundReaction(
                adapter=self.name,
                channel_id=str(reaction.message.channel.id),
                user_id=str(user.id),
                username=str(user),
                emoji=str(reaction.emoji),
                raw=reaction,
                received_at=datetime.now(UTC),
            )
            try:
                response = await self._reaction_handler(inbound)
                if response is not None:
                    await self.send(str(reaction.message.channel.id), response)
            except Exception:
                self.logger.exception("Error in reaction handler")

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
        embeds = self._build_embeds(message)
        files = self._build_files(message.attachments or [])
        for index, embed in enumerate(embeds):
            kwargs: dict[str, Any] = {"embed": embed}
            if index == 0 and files:
                kwargs["files"] = files
            await channel.send(**kwargs)

    async def send_to_default(self, message: OutboundMessage) -> None:
        """Send *message* to the configured default alert channel."""
        await self.send(str(self._default_channel_id), message)

    def _build_embed(self, message: OutboundMessage) -> _discord.Embed:
        title = _truncate(message.title, _EMBED_TITLE_MAX)
        description = _truncate(message.text, _EMBED_DESCRIPTION_MAX) or ""
        colour = _SEVERITY_COLOUR.get(message.severity, 0x95A5A6)
        embed = _discord.Embed(
            title=title,
            description=description,
            colour=colour,
        )

        current_total_chars = len(title or "") + len(description)
        if message.fields:
            for idx, (name, value) in enumerate(message.fields.items()):
                if idx >= _EMBED_FIELDS_MAX:
                    break
                safe_name = _truncate(name, _EMBED_FIELD_NAME_MAX) or "Field"
                safe_value = _truncate(value, _EMBED_FIELD_VALUE_MAX) or "—"
                if current_total_chars + len(safe_name) + len(safe_value) > _EMBED_TOTAL_CHARS_MAX:
                    break
                embed.add_field(name=safe_name, value=safe_value, inline=False)
                current_total_chars += len(safe_name) + len(safe_value)
        return embed

    def _build_embeds(self, message: OutboundMessage) -> list[_discord.Embed]:
        chunks = _split_for_embed_descriptions(message.text, _EMBED_DESCRIPTION_MAX)
        if len(chunks) == 1:
            return [self._build_embed(message)]

        embeds: list[_discord.Embed] = []
        total = len(chunks)
        for index, chunk in enumerate(chunks, start=1):
            title = message.title
            if title is not None:
                title = f"{title} ({index}/{total})"
            part_message = OutboundMessage(
                text=chunk,
                title=title
                if index == 1 or message.title is not None
                else f"Message ({index}/{total})",
                severity=message.severity,
                fields=message.fields if index == 1 else None,
                reply_to=message.reply_to,
            )
            embeds.append(self._build_embed(part_message))
        return embeds

    def _build_files(self, attachments: list[OutboundAttachment]) -> list[Any]:
        files: list[Any] = []
        for attachment in attachments:
            if attachment.content_type != "image/png":
                self.logger.warning(
                    "Skipping unsupported attachment content type: %s",
                    attachment.content_type,
                )
                continue
            files.append(_discord.File(fp=BytesIO(attachment.data), filename=attachment.filename))
        return files
