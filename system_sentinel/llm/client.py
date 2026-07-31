from __future__ import annotations

from typing import TYPE_CHECKING, Any

from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.llm.base import BaseLLMProvider, LLMRequest, LLMResponse
from system_sentinel.llm.router import ModelRouter

if TYPE_CHECKING:
    import logging


class LLMClient:
    """Facade for querying the configured active provider with policy-based model routing."""

    def __init__(
        self,
        llm_config: dict[str, Any],
        providers: dict[str, BaseLLMProvider],
        logger: logging.Logger,
    ) -> None:
        self._config = llm_config
        self._providers = providers
        self._logger = logger
        self._enabled = bool(llm_config.get("enabled", False))
        self._router = ModelRouter.from_config(llm_config)

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
    def active_model(self) -> str | None:
        """Default model as configured in ``llm.model``, or ``None`` if not set."""
        model = self._router.default_model
        return model or None

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
        command_type: str | None = None,
        severity: str | None = None,
    ) -> LLMResponse:
        """Send a completion request, applying routing rules if no explicit *model* is given.

        Args:
            prompt: The user-facing prompt text.
            system_prompt: Optional system/context prompt.
            model: Explicit model override; bypasses routing when provided.
            timeout_seconds: Per-request timeout override.
            command_type: Logical command name used for routing rule matching
                          (e.g. ``"ask"``, ``"explain_alert"``, ``"checkup"``).
            severity: Alert severity used for routing rule matching
                      (e.g. ``"critical"``, ``"warning"``).
        """
        route = self._router.resolve(command_type=command_type, severity=severity)

        effective_model = model if model is not None else (route.model or None)
        effective_provider_name = route.provider or self._active_provider_name

        provider = self._resolve_provider(effective_provider_name)
        request = LLMRequest(
            prompt=prompt,
            system_prompt=system_prompt,
            model=effective_model,
            timeout_seconds=timeout_seconds if timeout_seconds is not None else 30.0,
        )
        raw = await provider.complete(request)
        return LLMResponse(
            text=raw.text,
            model_used=raw.model_used,
            provider=raw.provider,
            prompt_tokens=raw.prompt_tokens,
            completion_tokens=raw.completion_tokens,
            matched_rule=route.matched_rule,
        )

    async def list_models(self) -> list[str]:
        provider = self._resolve_provider(self._active_provider_name)
        return await provider.list_models()

    async def health_check(self) -> bool:
        provider = self._resolve_provider(self._active_provider_name)
        return await provider.health_check()

    def _resolve_provider(self, provider_name: str | None = None) -> BaseLLMProvider:
        if not self._enabled:
            raise LLMUnavailableError("LLM assistant is disabled in config.")
        name = provider_name or self._active_provider_name
        if name is None:
            raise LLMUnavailableError("No LLM provider is configured.")
        provider = self._providers.get(name)
        if provider is None:
            raise LLMUnavailableError(
                f"Configured LLM provider {name!r} is not enabled or failed to load."
            )
        return provider


def _as_non_empty_string(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    return value or None
