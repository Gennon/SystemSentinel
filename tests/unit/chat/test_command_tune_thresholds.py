"""Tests for US-049: AI threshold tuning (!tune-thresholds command)."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from unittest.mock import AsyncMock

import pytest

from system_sentinel.chat.base import InboundMessage
from system_sentinel.chat.command_tune_thresholds import (
    MetricStats,
    ThresholdRecommendation,
    _compute_metric_stats,
    _extract_current_thresholds,
    _percentile,
    build_tune_thresholds_prompt,
    format_recommendations,
    gather_metric_stats,
    handle_tune_thresholds_command,
    parse_threshold_recommendations,
    perform_threshold_analysis,
)
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.llm.base import LLMResponse

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path):
    conn = DatabaseConnection(tmp_path / "test.db")
    await conn.connect()
    yield conn
    await conn.close()


def _message(text: str = "!tune-thresholds") -> InboundMessage:
    return InboundMessage(
        adapter="discord",
        channel_id="100",
        user_id="admin1",
        username="alice",
        text=text,
        raw={},
        received_at=datetime.now(UTC),
    )


class _FakeLLMClient:
    is_enabled = True
    active_provider_name = "ollama"

    def __init__(self, response_text: str = "[]") -> None:
        self._response_text = response_text

    async def complete(self, *, prompt, system_prompt=None, model=None, timeout_seconds=None):
        return LLMResponse(
            text=self._response_text,
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=100,
            completion_tokens=50,
        )


class _FailingLLMClient(_FakeLLMClient):
    async def complete(self, **kwargs):
        raise LLMUnavailableError("provider offline")


_SAMPLE_RECS_JSON = json.dumps(
    [
        {
            "metric": "cpu",
            "key_path": "monitors.cpu.alert_threshold_percent",
            "recommended_value": 80,
            "rationale": "Your p95 CPU is 72%, current threshold of 85% may be too loose",
        },
        {
            "metric": "ram",
            "key_path": "monitors.ram.alert_threshold_percent",
            "recommended_value": 90,
            "rationale": "RAM p95 is 65%, threshold of 80% could be raised",
        },
    ]
)

_SAMPLE_CONFIG = {
    "monitors": {
        "cpu": {"alert_threshold_percent": 85},
        "ram": {"alert_threshold_percent": 80},
        "disk": {"alert_threshold_percent": 90},
    }
}


# ---------------------------------------------------------------------------
# _percentile
# ---------------------------------------------------------------------------


def test_percentile_empty_list() -> None:
    assert _percentile([], 95) == 0.0


def test_percentile_single_element() -> None:
    assert _percentile([42.0], 95) == 42.0


def test_percentile_p50() -> None:
    values = [float(v) for v in range(1, 101)]
    assert _percentile(values, 50) == pytest.approx(50.5, abs=0.5)


def test_percentile_p100() -> None:
    assert _percentile([10.0, 20.0, 30.0], 100) == 30.0


# ---------------------------------------------------------------------------
# _compute_metric_stats
# ---------------------------------------------------------------------------


def test_compute_metric_stats_empty() -> None:
    assert _compute_metric_stats([]) is None


def test_compute_metric_stats_basic() -> None:
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    stats = _compute_metric_stats(values)
    assert stats is not None
    assert stats.count == 5
    assert stats.avg == pytest.approx(30.0)
    assert stats.peak == 50.0
    assert stats.minimum == 10.0
    assert stats.p95 > stats.avg


# ---------------------------------------------------------------------------
# _extract_current_thresholds
# ---------------------------------------------------------------------------


def test_extract_current_thresholds_basic() -> None:
    thresholds = _extract_current_thresholds(_SAMPLE_CONFIG)
    assert thresholds["cpu_alert_threshold_percent"] == 85
    assert thresholds["ram_alert_threshold_percent"] == 80
    assert thresholds["disk_alert_threshold_percent"] == 90


def test_extract_current_thresholds_empty_config() -> None:
    assert _extract_current_thresholds({}) == {}


def test_extract_current_thresholds_gpu() -> None:
    config = {"monitors": {"gpu": {"alert_threshold_percent": 95}}}
    thresholds = _extract_current_thresholds(config)
    assert thresholds["gpu_utilization_percent"] == 95


# ---------------------------------------------------------------------------
# gather_metric_stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gather_metric_stats_empty_db(db: DatabaseConnection) -> None:
    stats = await gather_metric_stats(metrics_repo=MetricsRepository(db), look_back_days=30)
    assert stats == {}


@pytest.mark.asyncio
async def test_gather_metric_stats_cpu(db: DatabaseConnection) -> None:
    repo = MetricsRepository(db)
    for val in [60.0, 70.0, 80.0]:
        await repo.insert("cpu", {"overall_percent": val, "top_processes": []})

    stats = await gather_metric_stats(metrics_repo=repo, look_back_days=30)
    assert "cpu" in stats
    assert isinstance(stats["cpu"], MetricStats)
    assert stats["cpu"].count == 3
    assert stats["cpu"].peak == 80.0


@pytest.mark.asyncio
async def test_gather_metric_stats_ram(db: DatabaseConnection) -> None:
    repo = MetricsRepository(db)
    for val in [50.0, 55.0, 60.0]:
        await repo.insert("ram", {"percent": val, "used_bytes": 0, "total_bytes": 0})

    stats = await gather_metric_stats(metrics_repo=repo, look_back_days=30)
    assert "ram" in stats
    assert stats["ram"].avg == pytest.approx(55.0)


@pytest.mark.asyncio
async def test_gather_metric_stats_disk(db: DatabaseConnection) -> None:
    repo = MetricsRepository(db)
    for val in [40.0, 45.0]:
        await repo.insert(
            "disk",
            {"partitions": [{"mountpoint": "/", "percent": val, "total_bytes": 0}]},
        )

    stats = await gather_metric_stats(metrics_repo=repo, look_back_days=30)
    assert "disk" in stats
    assert "/" in stats["disk"]


@pytest.mark.asyncio
async def test_gather_metric_stats_gpu(db: DatabaseConnection) -> None:
    repo = MetricsRepository(db)
    await repo.insert("gpu", {"utilization_percent": 85.0, "temperature_c": 70.0})

    stats = await gather_metric_stats(metrics_repo=repo, look_back_days=30)
    assert "gpu" in stats
    assert stats["gpu"].peak == 85.0


# ---------------------------------------------------------------------------
# build_tune_thresholds_prompt
# ---------------------------------------------------------------------------


def test_build_tune_thresholds_prompt_includes_sections() -> None:
    metric_stats = {
        "cpu": MetricStats(count=100, avg=60.0, p95=75.0, p99=80.0, peak=90.0, minimum=20.0),
        "ram": MetricStats(count=100, avg=55.0, p95=70.0, p99=75.0, peak=85.0, minimum=30.0),
    }
    prompt = build_tune_thresholds_prompt(
        metric_stats=metric_stats,
        current_thresholds={"cpu_alert_threshold_percent": 85, "ram_alert_threshold_percent": 80},
        look_back_days=30,
    )
    assert "=== METRIC STATISTICS ===" in prompt
    assert "CPU usage" in prompt
    assert "p95=75.0" in prompt
    assert "current_threshold=85" in prompt
    assert "=== INSTRUCTIONS ===" in prompt
    assert "monitors.cpu.alert_threshold_percent" in prompt


def test_build_tune_thresholds_prompt_no_data() -> None:
    prompt = build_tune_thresholds_prompt(metric_stats={}, current_thresholds={}, look_back_days=30)
    assert "CPU: no data available" in prompt
    assert "RAM: no data available" in prompt
    assert "Disk: no data available" in prompt


def test_build_tune_thresholds_prompt_disk_worst_mp() -> None:
    metric_stats = {
        "disk": {
            "/": MetricStats(count=50, avg=30.0, p95=35.0, p99=40.0, peak=50.0, minimum=20.0),
            "/data": MetricStats(count=50, avg=70.0, p95=85.0, p99=90.0, peak=95.0, minimum=60.0),
        }
    }
    prompt = build_tune_thresholds_prompt(
        metric_stats=metric_stats, current_thresholds={}, look_back_days=7
    )
    assert "/data" in prompt
    assert "p95=85.0" in prompt


# ---------------------------------------------------------------------------
# parse_threshold_recommendations
# ---------------------------------------------------------------------------


def test_parse_recommendations_valid_json() -> None:
    recs = parse_threshold_recommendations(_SAMPLE_RECS_JSON, {"cpu_alert_threshold_percent": 85})
    assert len(recs) == 2
    assert recs[0].metric == "cpu"
    assert recs[0].recommended_value == 80.0
    assert recs[0].current_value == 85.0
    assert "p95" in recs[0].rationale


def test_parse_recommendations_empty_array() -> None:
    assert parse_threshold_recommendations("[]", {}) == []


def test_parse_recommendations_markdown_fenced() -> None:
    text = "```json\n" + _SAMPLE_RECS_JSON + "\n```"
    assert len(parse_threshold_recommendations(text, {})) == 2


def test_parse_recommendations_invalid_json() -> None:
    assert parse_threshold_recommendations("not json", {}) == []


def test_parse_recommendations_missing_fields_skipped() -> None:
    bad = json.dumps(
        [
            {"metric": "cpu"},  # missing key_path and recommended_value
            {
                "metric": "ram",
                "key_path": "monitors.ram.alert_threshold_percent",
                "recommended_value": 90,
            },
        ]
    )
    recs = parse_threshold_recommendations(bad, {})
    assert len(recs) == 1
    assert recs[0].metric == "ram"


def test_parse_recommendations_json_embedded_in_text() -> None:
    text = f"Here are my suggestions:\n{_SAMPLE_RECS_JSON}\nDone."
    assert len(parse_threshold_recommendations(text, {})) == 2


def test_parse_recommendations_rationale_truncated() -> None:
    raw = json.dumps(
        [
            {
                "metric": "cpu",
                "key_path": "monitors.cpu.alert_threshold_percent",
                "recommended_value": 80,
                "rationale": "x" * 300,
            }
        ]
    )
    recs = parse_threshold_recommendations(raw, {})
    assert len(recs[0].rationale) <= 200


# ---------------------------------------------------------------------------
# format_recommendations
# ---------------------------------------------------------------------------


def test_format_recommendations_empty() -> None:
    text = format_recommendations([], look_back_days=30)
    assert "No changes recommended" in text


def test_format_recommendations_with_items() -> None:
    recs = [
        ThresholdRecommendation(
            metric="cpu",
            key_path="monitors.cpu.alert_threshold_percent",
            current_value=85.0,
            recommended_value=80.0,
            rationale="p95 is 72%",
        )
    ]
    text = format_recommendations(recs, look_back_days=30)
    assert "CPU" in text
    assert "85%" in text
    assert "80%" in text
    assert "p95 is 72%" in text
    assert "React with" in text


# ---------------------------------------------------------------------------
# perform_threshold_analysis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_perform_threshold_analysis_returns_recs(db: DatabaseConnection) -> None:
    repo = MetricsRepository(db)
    for v in range(50, 80):
        await repo.insert("cpu", {"overall_percent": float(v), "top_processes": []})

    audit = AsyncMock()
    recs = await perform_threshold_analysis(
        db=db,
        llm_client=_FakeLLMClient(_SAMPLE_RECS_JSON),  # type: ignore[arg-type]
        config=_SAMPLE_CONFIG,
        audit=audit,
        look_back_days=30,
        source="test",
    )

    assert len(recs) == 2
    audit.append.assert_awaited_once()
    kw = audit.append.call_args.kwargs
    assert kw["action_type"] == "threshold_tuning"
    assert kw["outcome"] == "success"


@pytest.mark.asyncio
async def test_perform_threshold_analysis_no_audit(db: DatabaseConnection) -> None:
    recs = await perform_threshold_analysis(
        db=db,
        llm_client=_FakeLLMClient("[]"),  # type: ignore[arg-type]
        config={},
    )
    assert recs == []


@pytest.mark.asyncio
async def test_perform_threshold_analysis_propagates_llm_error(db: DatabaseConnection) -> None:
    with pytest.raises(LLMUnavailableError):
        await perform_threshold_analysis(
            db=db,
            llm_client=_FailingLLMClient(),  # type: ignore[arg-type]
            config={},
        )


# ---------------------------------------------------------------------------
# handle_tune_thresholds_command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_tune_thresholds_command_no_llm(db: DatabaseConnection) -> None:
    resp = await handle_tune_thresholds_command(
        message=_message(), db=db, llm_client=None, config={}
    )
    assert "not configured" in resp.text.lower()


@pytest.mark.asyncio
async def test_handle_tune_thresholds_command_with_recommendations(
    db: DatabaseConnection,
) -> None:
    resp = await handle_tune_thresholds_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient(_SAMPLE_RECS_JSON),  # type: ignore[arg-type]
        config=_SAMPLE_CONFIG,
        look_back_days=30,
    )
    assert "CPU" in resp.text or "Threshold" in resp.text
    assert resp.reply_to is not None


@pytest.mark.asyncio
async def test_handle_tune_thresholds_command_no_recs(db: DatabaseConnection) -> None:
    resp = await handle_tune_thresholds_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient("[]"),  # type: ignore[arg-type]
        config={},
        look_back_days=30,
    )
    assert "No changes recommended" in resp.text


@pytest.mark.asyncio
async def test_handle_tune_thresholds_command_llm_unavailable(db: DatabaseConnection) -> None:
    resp = await handle_tune_thresholds_command(
        message=_message(),
        db=db,
        llm_client=_FailingLLMClient(),  # type: ignore[arg-type]
        config={},
    )
    assert "unavailable" in resp.text.lower()


@pytest.mark.asyncio
async def test_handle_tune_thresholds_command_truncates_long_report(
    db: DatabaseConnection,
) -> None:
    many_recs = json.dumps(
        [
            {
                "metric": f"metric_{i}",
                "key_path": f"monitors.metric_{i}.alert_threshold_percent",
                "recommended_value": 80 + i,
                "rationale": f"Reason {i}: " + "x" * 100,
            }
            for i in range(20)
        ]
    )
    resp = await handle_tune_thresholds_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient(many_recs),  # type: ignore[arg-type]
        config={},
    )
    assert len(resp.text) <= 3100
