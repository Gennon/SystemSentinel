from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from system_sentinel.charts.base import BaseChartRenderer, ChartPeriod, ChartRequest
from system_sentinel.chat.base import InboundMessage, OutboundAttachment, OutboundMessage

if TYPE_CHECKING:
    from system_sentinel.db.metrics_repository import MetricsRepository

_SUPPORTED_METRICS = ("cpu", "ram", "disk", "network", "gpu")
_SUPPORTED_PERIODS = ("24h", "7d", "30d", "90d")


def _format_duration(seconds: int) -> str:
    if seconds < 3600:
        minutes = max(1, seconds // 60)
        return f"{minutes}m"
    if seconds < 24 * 3600:
        return f"{seconds // 3600}h"
    days = seconds // (24 * 3600)
    remainder_hours = (seconds % (24 * 3600)) // 3600
    if remainder_hours == 0:
        return f"{days}d"
    return f"{days}d {remainder_hours}h"


async def handle_graph_command(
    *,
    message: InboundMessage,
    metrics_repo: MetricsRepository,
    chart_renderer: BaseChartRenderer,
) -> OutboundMessage:
    parts = message.text.strip().split()
    if len(parts) != 3:
        return OutboundMessage(
            text="Usage: !graph <metric> <period> (metrics: cpu, ram, disk, network, gpu; periods: 24h, 7d, 30d, 90d)",
            reply_to=message,
        )

    metric = parts[1].strip().lower()
    if metric not in _SUPPORTED_METRICS:
        return OutboundMessage(
            text=f"Unsupported metric: {metric}. Supported metrics: {', '.join(_SUPPORTED_METRICS)}.",
            reply_to=message,
        )

    period_token = parts[2].strip().lower()
    try:
        period = ChartPeriod(period_token)
    except ValueError:
        return OutboundMessage(
            text=f"Unsupported period: {period_token}. Supported periods: {', '.join(_SUPPORTED_PERIODS)}.",
            reply_to=message,
        )

    now = datetime.now(UTC)
    since = now - timedelta(seconds=period.seconds)
    points = await metrics_repo.query_graph_points(metric, since=since, until=now)
    if not points:
        return OutboundMessage(
            text=f"No {metric} data is available yet for {period.value}.",
            reply_to=message,
        )

    first_timestamp = points[0][0]
    note: str | None = None
    if first_timestamp > since + timedelta(minutes=5):
        available_seconds = max(0, int((now - first_timestamp).total_seconds()))
        note = (
            f"Note: insufficient data for full {period.value}; showing available window "
            f"({_format_duration(available_seconds)})."
        )

    request = ChartRequest(metric=metric, period=period, data=points)
    try:
        result = await chart_renderer.render(request)
    except Exception as exc:
        return OutboundMessage(
            text=f"Failed to render chart with renderer '{chart_renderer.name}': {exc}",
            reply_to=message,
        )

    if result.content_type == "image/png":
        if not isinstance(result.payload, bytes):
            return OutboundMessage(
                text="Chart renderer returned invalid image payload.",
                reply_to=message,
            )
        summary = f"{metric.upper()} history ({period.value})"
        if note is not None:
            summary = f"{summary}\n{note}"
        return OutboundMessage(
            text=summary,
            attachments=[
                OutboundAttachment(
                    filename=result.filename or f"{metric}-{period.value}.png",
                    content_type="image/png",
                    data=result.payload,
                )
            ],
            reply_to=message,
        )

    if not isinstance(result.payload, str):
        return OutboundMessage(
            text="Chart renderer returned invalid text payload.",
            reply_to=message,
        )

    text_payload = result.payload
    if note is not None:
        text_payload = f"{text_payload}\n{note}"
    return OutboundMessage(text=text_payload, reply_to=message)
