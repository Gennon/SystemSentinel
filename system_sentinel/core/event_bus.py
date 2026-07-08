from __future__ import annotations

from collections.abc import Awaitable, Callable
import logging
from typing import Any

EventHandler = Callable[[str, Any], Awaitable[None]]


class InProcessEventBus:
    """Lightweight in-process publish/subscribe bus.

    Satisfies the ``EventBus`` protocol defined in ``core.context`` and
    additionally exposes :py:meth:`subscribe` so application components
    can register interest in specific event types.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = {}
        self._logger = logging.getLogger("sentinel.event_bus")

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Register *handler* to be called whenever *event_type* is published."""
        self._subscribers.setdefault(event_type, []).append(handler)

    async def publish(self, event_type: str, payload: Any) -> None:
        """Deliver *payload* to every subscriber registered for *event_type*."""
        for handler in self._subscribers.get(event_type, []):
            try:
                await handler(event_type, payload)
            except Exception:
                self._logger.exception(
                    "Event handler %r raised an exception for event %r",
                    handler,
                    event_type,
                )
