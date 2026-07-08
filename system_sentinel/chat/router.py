from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from system_sentinel.chat.base import BaseChatAdapter, OutboundMessage


class ChatRouter:
    """Routes outbound messages to one or all registered chat adapters."""

    def __init__(self) -> None:
        self._adapters: list[BaseChatAdapter] = []
        self._logger = logging.getLogger("sentinel.chat.router")

    def register(self, adapter: BaseChatAdapter) -> None:
        """Add an adapter to the routing table."""
        self._adapters.append(adapter)

    async def broadcast(self, message: OutboundMessage) -> None:
        """Send *message* to every registered adapter's default channel."""
        for adapter in self._adapters:
            try:
                await adapter.send_to_default(message)
            except Exception:
                self._logger.exception("Failed to send broadcast via adapter %r", adapter.name)

    async def send(self, adapter_name: str, channel_id: str, message: OutboundMessage) -> None:
        """Send *message* to a specific channel on the named adapter."""
        for adapter in self._adapters:
            if adapter.name == adapter_name:
                await adapter.send(channel_id, message)
                return
        raise KeyError(f"No adapter registered with name: {adapter_name!r}")

    @property
    def adapters(self) -> list[BaseChatAdapter]:
        return list(self._adapters)
