from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext


@dataclass(frozen=True)
class LLMRequest:
    prompt: str
    system_prompt: str | None = None
    model: str | None = None
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model_used: str
    provider: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class BaseLLMProvider(ABC):
    name: str

    def __init__(self, config: dict[str, object], app_ctx: AppContext) -> None:
        self.config = config
        self.ctx = app_ctx
        self.logger = app_ctx.logger.getChild(f"llm.{self.name}")

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a completion request and return a normalized response."""
        ...

    @abstractmethod
    async def list_models(self) -> list[str]:
        """Return provider model identifiers."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True when the provider is reachable and usable."""
        ...
