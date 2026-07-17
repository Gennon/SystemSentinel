from __future__ import annotations

from io import BytesIO

from system_sentinel.charts.base import BaseChartRenderer, ChartRequest, ChartResult


class ImageChartRenderer(BaseChartRenderer):
    """Render a PNG chart using matplotlib."""

    name = "image"

    async def render(self, request: ChartRequest) -> ChartResult:
        try:
            import matplotlib  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - exercised in integration environments
            raise RuntimeError(
                "Image chart renderer requires matplotlib. "
                "Install it with: pip install 'system-sentinel[graphs]'"
            ) from exc
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore[import-not-found]

        timestamps = [timestamp for timestamp, _value in request.data]
        values = [value for _timestamp, value in request.data]

        figure, axis = plt.subplots(figsize=(9, 3.8))
        axis.plot(timestamps, values, linewidth=1.5)
        axis.set_title(f"{request.metric.upper()} history ({request.period.value})")
        axis.grid(True, alpha=0.3)
        figure.autofmt_xdate()

        buffer = BytesIO()
        figure.savefig(buffer, format="png", dpi=120, bbox_inches="tight")
        plt.close(figure)
        return ChartResult(
            content_type="image/png",
            payload=buffer.getvalue(),
            filename=f"{request.metric}-{request.period.value}.png",
        )
