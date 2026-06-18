from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext


class ToolOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"


@dataclass
class ToolResult:
    tool_name: str
    outcome: ToolOutcome
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    error: str | None = None


class BaseTool(ABC):
    name: str
    display_name: str
    description: str

    def __init__(self, config: dict[str, Any], app_ctx: AppContext) -> None:
        self.config = config
        self.ctx = app_ctx

    @abstractmethod
    async def run(self) -> ToolResult: ...

    async def dry_run(self) -> ToolResult:
        return await self.run()

    def is_enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    def schedule(self) -> str | None:
        val = self.config.get("schedule")
        return str(val) if val is not None else None
