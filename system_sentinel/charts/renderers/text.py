from __future__ import annotations

from system_sentinel.charts.base import BaseChartRenderer, ChartRequest, ChartResult


def _downsample(
    points: list[tuple[str, float]],
    *,
    max_points: int,
) -> list[tuple[str, float]]:
    if len(points) <= max_points:
        return points
    step = max(1, len(points) // max_points)
    return points[::step][:max_points]


class TextChartRenderer(BaseChartRenderer):
    """Render a unicode text chart using plotext."""

    name = "text"

    async def render(self, request: ChartRequest) -> ChartResult:
        import plotext as plt  # type: ignore[import-untyped]

        points = _downsample(
            [(timestamp.strftime("%m-%d %H:%M"), value) for timestamp, value in request.data],
            max_points=80,
        )
        values = [value for _label, value in points]

        plt.clear_figure()
        plt.plot(values)
        plt.title(f"{request.metric.upper()} ({request.period.value})")
        plt.plotsize(90, 18)
        chart = plt.build()
        plt.clear_figure()
        payload = (
            f"{request.metric.upper()} history ({request.period.value})\n```text\n{chart}\n```"
        )
        return ChartResult(content_type="text/plain", payload=payload)
