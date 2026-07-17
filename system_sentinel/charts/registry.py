from __future__ import annotations

from importlib.metadata import entry_points
from typing import TYPE_CHECKING

from system_sentinel.charts.renderers.image import ImageChartRenderer
from system_sentinel.charts.renderers.text import TextChartRenderer

if TYPE_CHECKING:
    from logging import Logger

    from system_sentinel.charts.base import BaseChartRenderer


class ChartRendererRegistry:
    """Discover and expose configured chart renderers."""

    _ENTRY_POINT_GROUP = "sentinel.chart_renderers"

    def __init__(self, logger: Logger) -> None:
        self._logger = logger
        self._renderers: dict[str, BaseChartRenderer] = {}

    def discover(self) -> None:
        self._renderers = {
            TextChartRenderer.name: TextChartRenderer(),
            ImageChartRenderer.name: ImageChartRenderer(),
        }

        for entry_point in entry_points(group=self._ENTRY_POINT_GROUP):
            try:
                renderer_cls = entry_point.load()
                renderer: BaseChartRenderer = renderer_cls()
            except Exception:
                self._logger.exception("Failed to load chart renderer %r", entry_point.name)
                continue
            self._renderers[renderer.name] = renderer

    def get(self, name: str) -> BaseChartRenderer | None:
        return self._renderers.get(name)
