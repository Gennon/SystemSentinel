from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from system_sentinel.charts.base import ChartPeriod, ChartRequest
from system_sentinel.charts.renderers.text import TextChartRenderer


@pytest.mark.asyncio
async def test_text_renderer_outputs_ascii_chart_payload() -> None:
    now = datetime.now(UTC)
    request = ChartRequest(
        metric="cpu",
        period=ChartPeriod.H24,
        data=[
            (now - timedelta(hours=3), 22.0),
            (now - timedelta(hours=2), 35.5),
            (now - timedelta(hours=1), 44.0),
            (now, 30.0),
        ],
    )

    result = await TextChartRenderer().render(request)

    assert result.content_type == "text/plain"
    assert isinstance(result.payload, str)
    payload = result.payload
    assert payload.startswith("CPU history (24h)\n```text\n")
    assert "min 22.00" in payload
    assert "avg 32.88" in payload
    assert "max 44.00" in payload
    payload.encode("ascii")


@pytest.mark.asyncio
async def test_text_renderer_downsamples_for_readability() -> None:
    now = datetime.now(UTC)
    request = ChartRequest(
        metric="ram",
        period=ChartPeriod.D7,
        data=[(now - timedelta(hours=index), float(index)) for index in range(60)],
    )

    result = await TextChartRenderer().render(request)

    assert isinstance(result.payload, str)
    chart_body = result.payload.split("```text\n", maxsplit=1)[1].rsplit("\n```", maxsplit=1)[0]
    chart_lines = [line for line in chart_body.splitlines() if " | " in line]
    assert len(chart_lines) <= 18
