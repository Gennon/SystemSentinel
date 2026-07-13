from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

    from system_sentinel.core.context import AppContext


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class InboundMessage:
    adapter: str
    channel_id: str
    user_id: str
    username: str
    text: str
    raw: object
    received_at: datetime


@dataclass
class OutboundMessage:
    text: str
    title: str | None = None
    severity: AlertSeverity = AlertSeverity.INFO
    fields: dict[str, str] | None = None
    reply_to: InboundMessage | None = None


CommandHandler = Callable[[InboundMessage, list[str]], Awaitable["OutboundMessage | None"]]
ReactionHandler = Callable[["InboundReaction"], Awaitable["OutboundMessage | None"]]


@dataclass
class InboundReaction:
    adapter: str
    channel_id: str
    user_id: str
    username: str
    emoji: str
    raw: object
    received_at: datetime


class BaseChatAdapter(ABC):
    name: str

    def __init__(self, config: dict[str, Any], app_ctx: AppContext) -> None:
        self.config = config
        self.ctx = app_ctx
        self.logger = app_ctx.logger.getChild(f"chat.{self.name}")
        self._message_handler: CommandHandler | None = None
        self._reaction_handler: ReactionHandler | None = None

    @abstractmethod
    async def start(self) -> None:
        """Connect and begin listening. Called once on daemon start."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Disconnect cleanly."""
        ...

    @abstractmethod
    async def send(self, channel_id: str, message: OutboundMessage) -> None:
        """Send a message to a specific channel."""
        ...

    @abstractmethod
    async def send_to_default(self, message: OutboundMessage) -> None:
        """Send to the adapter's configured default alert channel."""
        ...

    def on_message(self, handler: CommandHandler) -> None:
        """Register the dispatcher callback. Called by ChatRouter during wiring."""
        self._message_handler = handler

    def on_reaction(self, handler: ReactionHandler) -> None:
        """Register the reaction callback."""
        self._reaction_handler = handler
