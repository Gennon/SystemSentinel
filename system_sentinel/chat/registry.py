from __future__ import annotations

from importlib.metadata import entry_points
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.chat.base import BaseChatAdapter
    from system_sentinel.core.context import AppContext


class ChatRegistry:
    """Discovers and instantiates chat adapters via entry points."""

    _ENTRY_POINT_GROUP = "sentinel.chat_adapters"

    def __init__(self, config: dict[str, Any], app_ctx: AppContext) -> None:
        self._config = config
        self._ctx = app_ctx
        self._adapters: dict[str, BaseChatAdapter] = {}
        self._logger = logging.getLogger("sentinel.chat.registry")

    def discover(self) -> None:
        """Load all enabled chat adapters registered via entry points."""
        eps = entry_points(group=self._ENTRY_POINT_GROUP)
        for ep in eps:
            adapter_config: dict[str, Any] = self._config.get(ep.name, {})
            if not adapter_config.get("enabled", False):
                self._logger.debug("Chat adapter %r is disabled — skipping", ep.name)
                continue
            try:
                cls = ep.load()
                adapter: BaseChatAdapter = cls(adapter_config, self._ctx)
                self._adapters[ep.name] = adapter
                self._logger.info("Loaded chat adapter: %s", ep.name)
            except Exception:
                self._logger.exception("Failed to load chat adapter %r", ep.name)

    @property
    def adapters(self) -> dict[str, BaseChatAdapter]:
        return dict(self._adapters)
