from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuditRepository(Protocol):
    async def append(
        self,
        action_type: str,
        source: str,
        description: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> None: ...


@runtime_checkable
class EventBus(Protocol):
    async def publish(self, event_type: str, payload: Any) -> None: ...


@runtime_checkable
class LLMClient(Protocol):
    @property
    def active_provider_name(self) -> str | None: ...

    @property
    def is_enabled(self) -> bool: ...

    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> Any: ...

    async def list_models(self) -> list[str]: ...

    async def health_check(self) -> bool: ...


@dataclass
class AppContext:
    audit: AuditRepository
    event_bus: EventBus
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("sentinel"))
    llm: LLMClient | None = None
