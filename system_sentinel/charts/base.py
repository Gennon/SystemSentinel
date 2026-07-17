from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


class ChartPeriod(StrEnum):
    H24 = "24h"
    D7 = "7d"
    D30 = "30d"
    D90 = "90d"

    @property
    def seconds(self) -> int:
        mapping = {
            ChartPeriod.H24: 24 * 60 * 60,
            ChartPeriod.D7: 7 * 24 * 60 * 60,
            ChartPeriod.D30: 30 * 24 * 60 * 60,
            ChartPeriod.D90: 90 * 24 * 60 * 60,
        }
        return mapping[self]


@dataclass(frozen=True)
class ChartRequest:
    metric: str
    period: ChartPeriod
    data: list[tuple[datetime, float]]


@dataclass(frozen=True)
class ChartResult:
    content_type: str
    payload: str | bytes
    filename: str | None = None


class BaseChartRenderer(ABC):
    name: str

    @abstractmethod
    async def render(self, request: ChartRequest) -> ChartResult:
        """Render a chart for the requested metric period."""
        ...
