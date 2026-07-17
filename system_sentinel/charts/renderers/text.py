from __future__ import annotations

from statistics import fmean

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


def _build_ascii_bar_chart(points: list[tuple[str, float]], *, bar_width: int) -> str:
    values = [value for _label, value in points]
    min_value = min(values)
    max_value = max(values)
    span = max_value - min_value

    lines: list[str] = []
    for label, value in points:
        ratio = 1.0 if span == 0 else (value - min_value) / span
        filled = round(ratio * bar_width)
        bar = "#" * filled
        lines.append(f"{label} | {bar:<{bar_width}} | {value:7.2f}")

    summary = (
        f"min {min_value:.2f}  avg {fmean(values):.2f}  max {max_value:.2f}  samples {len(points)}"
    )
    return "\n".join([*lines, "", summary])


class TextChartRenderer(BaseChartRenderer):
    """Render a Discord-friendly ASCII bar chart in a code block."""

    name = "text"

    async def render(self, request: ChartRequest) -> ChartResult:
        points = _downsample(
            [(timestamp.strftime("%m-%d %H:%M"), value) for timestamp, value in request.data],
            max_points=18,
        )
        chart = _build_ascii_bar_chart(points, bar_width=30)
        payload = (
            f"{request.metric.upper()} history ({request.period.value})\n```text\n{chart}\n```"
        )
        return ChartResult(content_type="text/plain", payload=payload)
