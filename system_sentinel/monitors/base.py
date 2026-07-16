from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext


class BaseMonitor(ABC):
    """Base class for all monitor plugins (Monitor Engine sensor plugins)."""

    name: str

    def __init__(self, config: dict[str, Any], app_ctx: AppContext) -> None:
        self.config = config
        self.ctx = app_ctx
        self.logger = app_ctx.logger.getChild(f"monitor.{self.name}")

    @abstractmethod
    async def collect(self) -> None:
        """Collect a single sample.  Must not raise — log errors and return."""
        ...

    async def stop(self) -> None:
        """Optional monitor-specific teardown hook."""
        return None

    def is_enabled(self) -> bool:
        return bool(self.config.get("enabled", True))
