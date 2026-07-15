from __future__ import annotations

from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.llm.base import BaseLLMProvider


class LLMRegistry:
    """Discovers and instantiates LLM providers via entry points."""

    _ENTRY_POINT_GROUP = "sentinel.llm_providers"

    def __init__(self, config: dict[str, Any], app_ctx: AppContext) -> None:
        self._config = config
        self._ctx = app_ctx
        self._providers: dict[str, BaseLLMProvider] = {}
        self._logger = app_ctx.logger.getChild("llm.registry")

    def discover(self) -> None:
        eps = entry_points(group=self._ENTRY_POINT_GROUP)
        for ep in eps:
            raw_provider_config = self._config.get(ep.name, {})
            provider_config: dict[str, Any] = (
                dict(raw_provider_config) if isinstance(raw_provider_config, dict) else {}
            )
            if not provider_config.get("enabled", False):
                self._logger.debug("LLM provider %r is disabled — skipping", ep.name)
                continue
            try:
                cls = ep.load()
                provider: BaseLLMProvider = cls(provider_config, self._ctx)
                self._providers[ep.name] = provider
                self._logger.info("Loaded LLM provider: %s", ep.name)
            except Exception:
                self._logger.exception("Failed to load LLM provider %r", ep.name)

    @property
    def providers(self) -> dict[str, BaseLLMProvider]:
        return dict(self._providers)
