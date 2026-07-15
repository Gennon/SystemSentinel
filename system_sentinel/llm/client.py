from __future__ import annotations

from typing import TYPE_CHECKING, Any

from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.llm.base import BaseLLMProvider, LLMRequest, LLMResponse

if TYPE_CHECKING:
    import logging


class LLMClient:
    """Facade for querying the configured active provider."""

    def __init__(
        self,
        llm_config: dict[str, Any],
        providers: dict[str, BaseLLMProvider],
        logger: logging.Logger,
    ) -> None:
        self._config = llm_config
        self._providers = providers
        self._logger = logger
        self._default_model = _as_non_empty_string(llm_config.get("model"))
        self._enabled = bool(llm_config.get("enabled", False))
        configured_provider = _as_non_empty_string(llm_config.get("provider"))
        self._active_provider_name: str | None
        if configured_provider is not None:
            self._active_provider_name = configured_provider
        elif providers:
            self._active_provider_name = sorted(providers.keys())[0]
        else:
            self._active_provider_name = None

    @property
    def active_provider_name(self) -> str | None:
        return self._active_provider_name

    @property
    def is_enabled(self) -> bool:
        return self._enabled and self._active_provider_name in self._providers

    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMResponse:
        provider = self._resolve_provider()
        selected_model = model or self._default_model
        request = LLMRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            model=selected_model,
            timeout_seconds=timeout_seconds if timeout_seconds is not None else 30.0,
        )
        return await provider.complete(request)

    async def list_models(self) -> list[str]:
        provider = self._resolve_provider()
        return await provider.list_models()

    async def health_check(self) -> bool:
        provider = self._resolve_provider()
        return await provider.health_check()

    def _resolve_provider(self) -> BaseLLMProvider:
        if not self._enabled:
            raise LLMUnavailableError("LLM assistant is disabled in config.")
        provider_name = self._active_provider_name
        if provider_name is None:
            raise LLMUnavailableError("No LLM provider is configured.")
        provider = self._providers.get(provider_name)
        if provider is None:
            raise LLMUnavailableError(
                f"Configured LLM provider {provider_name!r} is not enabled or failed to load."
            )
        return provider


def _as_non_empty_string(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    return value or None
