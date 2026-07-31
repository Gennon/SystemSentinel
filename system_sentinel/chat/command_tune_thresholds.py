"""AI-driven threshold tuning command (US-049).

Analyzes historical metric data and recommends more accurate alert thresholds
based on real usage patterns rather than generic defaults.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import statistics
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.chat.base import InboundMessage, OutboundMessage
    from system_sentinel.core.context import AuditRepository, LLMClient
    from system_sentinel.db.connection import DatabaseConnection
    from system_sentinel.db.metrics_repository import MetricsRepository

_TUNE_SYSTEM_PROMPT = (
    "You are SystemSentinel, a Linux system management assistant. "
    "You have been given statistical summaries of historical system metric data. "
    "Your task is to recommend improved alert thresholds based on real usage patterns. "
    "For each metric, consider the p95 value as a baseline. Thresholds set too low cause "
    "alert fatigue; thresholds set too high miss real problems. "
    "Respond ONLY with a valid JSON array of recommendation objects. "
    "Each object must have exactly these fields: "
    '"metric" (string, e.g. "cpu"), '
    '"key_path" (string, the config key to change), '
    '"recommended_value" (number), '
    '"rationale" (string, ≤ 120 chars). '
    "Include only metrics where the current threshold seems suboptimal. "
    "If all thresholds look reasonable, return an empty array []."
)

_MAX_REPORT_CHARS = 3000
_DEFAULT_LOOK_BACK_DAYS = 30


@dataclass(frozen=True)
class ThresholdRecommendation:
    metric: str
    key_path: str
    current_value: float | None
    recommended_value: float
    rationale: str


@dataclass
class MetricStats:
    count: int
    avg: float
    p95: float
    p99: float
    peak: float
    minimum: float


def _percentile(values: list[float], p: float) -> float:
    """Compute the p-th percentile of a sorted-or-unsorted list."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = (len(sorted_vals) - 1) * p / 100.0
    lo = int(idx)
    hi = lo + 1
    if hi >= len(sorted_vals):
        return sorted_vals[lo]
    frac = idx - lo
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac


def _compute_metric_stats(values: list[float]) -> MetricStats | None:
    if not values:
        return None
    return MetricStats(
        count=len(values),
        avg=statistics.mean(values),
        p95=_percentile(values, 95),
        p99=_percentile(values, 99),
        peak=max(values),
        minimum=min(values),
    )


async def gather_metric_stats(
    *,
    metrics_repo: MetricsRepository,
    look_back_days: int = _DEFAULT_LOOK_BACK_DAYS,
) -> dict[str, Any]:
    """Query historical metrics and return per-metric statistics."""
    since = datetime.now(UTC) - timedelta(days=look_back_days)

    cpu_samples = await metrics_repo.query_range("cpu", since=since)
    ram_samples = await metrics_repo.query_range("ram", since=since)
    disk_samples = await metrics_repo.query_range("disk", since=since)
    gpu_samples = await metrics_repo.query_range("gpu", since=since)

    stats: dict[str, Any] = {}

    # CPU
    cpu_values = [float(s["overall_percent"]) for s in cpu_samples if "overall_percent" in s]
    cpu_stats = _compute_metric_stats(cpu_values)
    if cpu_stats:
        stats["cpu"] = cpu_stats

    # RAM
    ram_values = [float(s["percent"]) for s in ram_samples if "percent" in s]
    ram_stats = _compute_metric_stats(ram_values)
    if ram_stats:
        stats["ram"] = ram_stats

    # Disk (per mountpoint)
    disk_by_mp: dict[str, list[float]] = {}
    for sample in disk_samples:
        for partition in sample.get("partitions", []):
            if not isinstance(partition, dict):
                continue
            mp = str(partition.get("mountpoint", "/"))
            pct = partition.get("percent")
            if pct is not None:
                disk_by_mp.setdefault(mp, []).append(float(pct))
    disk_stats: dict[str, MetricStats] = {}
    for mp, values in disk_by_mp.items():
        s = _compute_metric_stats(values)
        if s:
            disk_stats[mp] = s
    if disk_stats:
        stats["disk"] = disk_stats

    # GPU (optional)
    gpu_util_values = [
        float(s["utilization_percent"]) for s in gpu_samples if "utilization_percent" in s
    ]
    gpu_stats = _compute_metric_stats(gpu_util_values)
    if gpu_stats:
        stats["gpu"] = gpu_stats

    return stats


def build_tune_thresholds_prompt(
    *,
    metric_stats: dict[str, Any],
    current_thresholds: dict[str, Any],
    look_back_days: int,
) -> str:
    """Build the LLM prompt from gathered metric statistics."""
    lines: list[str] = [
        f"Threshold tuning analysis — data window: last {look_back_days} days",
        f"Analysis time: {datetime.now(UTC).isoformat()}",
        "",
        "=== METRIC STATISTICS ===",
    ]

    # CPU
    cpu = metric_stats.get("cpu")
    if isinstance(cpu, MetricStats):
        cpu_thresh = current_thresholds.get("cpu_alert_threshold_percent")
        lines.append(
            f"CPU usage (%, {cpu.count} samples): "
            f"avg={cpu.avg:.1f}, p95={cpu.p95:.1f}, p99={cpu.p99:.1f}, peak={cpu.peak:.1f}"
            f" | current_threshold={cpu_thresh}"
        )
        lines.append('  config key: "monitors.cpu.alert_threshold_percent"')
    else:
        lines.append("CPU: no data available")

    # RAM
    ram = metric_stats.get("ram")
    if isinstance(ram, MetricStats):
        ram_thresh = current_thresholds.get("ram_alert_threshold_percent")
        lines.append(
            f"RAM usage (%, {ram.count} samples): "
            f"avg={ram.avg:.1f}, p95={ram.p95:.1f}, p99={ram.p99:.1f}, peak={ram.peak:.1f}"
            f" | current_threshold={ram_thresh}"
        )
        lines.append('  config key: "monitors.ram.alert_threshold_percent"')
    else:
        lines.append("RAM: no data available")

    # Disk (use worst-case mountpoint by p95)
    disk = metric_stats.get("disk")
    disk_thresh = current_thresholds.get("disk_alert_threshold_percent")
    if isinstance(disk, dict) and disk:
        worst_mp, worst_stats = max(
            disk.items(), key=lambda kv: kv[1].p95 if isinstance(kv[1], MetricStats) else 0.0
        )
        if isinstance(worst_stats, MetricStats):
            lines.append(
                f"Disk usage (%, mountpoint={worst_mp!r}, {worst_stats.count} samples): "
                f"avg={worst_stats.avg:.1f}, p95={worst_stats.p95:.1f}, "
                f"p99={worst_stats.p99:.1f}, peak={worst_stats.peak:.1f}"
                f" | current_threshold={disk_thresh}"
            )
            lines.append('  config key: "monitors.disk.alert_threshold_percent"')
        for mp, mp_stats in disk.items():
            if mp == worst_mp or not isinstance(mp_stats, MetricStats):
                continue
            lines.append(
                f"  Disk {mp!r}: avg={mp_stats.avg:.1f}, p95={mp_stats.p95:.1f}, "
                f"peak={mp_stats.peak:.1f}"
            )
    else:
        lines.append("Disk: no data available")

    # GPU
    gpu = metric_stats.get("gpu")
    if isinstance(gpu, MetricStats):
        gpu_thresh = current_thresholds.get("gpu_utilization_percent")
        lines.append(
            f"GPU utilization (%, {gpu.count} samples): "
            f"avg={gpu.avg:.1f}, p95={gpu.p95:.1f}, p99={gpu.p99:.1f}, peak={gpu.peak:.1f}"
            f" | current_threshold={gpu_thresh}"
        )
        lines.append('  config key: "monitors.gpu.alert_threshold_percent"')

    lines += [
        "",
        "=== INSTRUCTIONS ===",
        "Based on the statistics above, recommend improved alert thresholds.",
        "Return ONLY a JSON array. Each object must have: metric, key_path, "
        "recommended_value, rationale.",
        "Only include metrics where the threshold needs adjustment.",
        "If all thresholds look fine, return [].",
    ]

    return "\n".join(lines)


def _extract_current_thresholds(config: dict[str, Any]) -> dict[str, Any]:
    """Extract current alert threshold values from config."""
    monitors = config.get("monitors", {})
    if not isinstance(monitors, dict):
        monitors = {}

    thresholds: dict[str, Any] = {}
    for monitor_name in ("cpu", "ram", "disk"):
        monitor_cfg = monitors.get(monitor_name, {})
        if not isinstance(monitor_cfg, dict):
            continue
        key = f"{monitor_name}_alert_threshold_percent"
        val = monitor_cfg.get("alert_threshold_percent")
        if val is not None:
            thresholds[key] = val

    gpu_cfg = monitors.get("gpu", {})
    if isinstance(gpu_cfg, dict):
        gpu_thresh = gpu_cfg.get("alert_threshold_percent")
        if gpu_thresh is not None:
            thresholds["gpu_utilization_percent"] = gpu_thresh

    return thresholds


def parse_threshold_recommendations(
    llm_text: str,
    current_thresholds: dict[str, Any],
) -> list[ThresholdRecommendation]:
    """Parse LLM JSON output into ThresholdRecommendation objects."""
    text = llm_text.strip()

    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Try to extract JSON array from the text
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            return []
        try:
            data = json.loads(text[start : end + 1])
        except (json.JSONDecodeError, ValueError):
            return []

    if not isinstance(data, list):
        return []

    recommendations: list[ThresholdRecommendation] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        metric = item.get("metric")
        key_path = item.get("key_path")
        recommended_value = item.get("recommended_value")
        rationale = item.get("rationale", "")

        if not isinstance(metric, str) or not metric.strip():
            continue
        if not isinstance(key_path, str) or not key_path.strip():
            continue
        try:
            rec_val = float(recommended_value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue

        # Determine current value from thresholds dict using heuristic
        current: float | None = None
        for thresh_key, thresh_val in current_thresholds.items():
            if metric.lower() in thresh_key.lower():
                with contextlib.suppress(TypeError, ValueError):
                    current = float(thresh_val)
                break

        recommendations.append(
            ThresholdRecommendation(
                metric=str(metric).strip(),
                key_path=str(key_path).strip(),
                current_value=current,
                recommended_value=rec_val,
                rationale=str(rationale).strip()[:200],
            )
        )

    return recommendations


def format_recommendations(
    recommendations: list[ThresholdRecommendation],
    look_back_days: int,
) -> str:
    """Format recommendations into a human-readable chat message."""
    if not recommendations:
        return (
            f"✅ All alert thresholds look appropriate based on the last {look_back_days} days "
            "of data. No changes recommended."
        )

    lines = [
        f"📊 **Threshold Tuning Recommendations** (last {look_back_days} days)\n",
        "The AI analyzed your metric history and suggests the following changes:\n",
    ]
    for i, rec in enumerate(recommendations, 1):
        current_str = f"{rec.current_value:.0f}%" if rec.current_value is not None else "not set"
        lines.append(
            f"{i}. **{rec.metric.upper()}** — `{rec.key_path}`\n"
            f"   Current: {current_str} → Recommended: {rec.recommended_value:.0f}%\n"
            f"   _{rec.rationale}_\n"
        )
    lines.append(f"React with ✅ to apply all {len(recommendations)} recommendation(s).")
    return "\n".join(lines)


async def perform_threshold_analysis(
    *,
    db: DatabaseConnection,
    llm_client: LLMClient,
    config: dict[str, Any],
    audit: AuditRepository | None = None,
    look_back_days: int = _DEFAULT_LOOK_BACK_DAYS,
    source: str = "chat",
    timeout_seconds: float = 60.0,
) -> list[ThresholdRecommendation]:
    """Analyze metric history and return AI-generated threshold recommendations."""
    from system_sentinel.db.metrics_repository import MetricsRepository

    metrics_repo = MetricsRepository(db)
    metric_stats = await gather_metric_stats(
        metrics_repo=metrics_repo,
        look_back_days=look_back_days,
    )
    current_thresholds = _extract_current_thresholds(config)

    prompt = build_tune_thresholds_prompt(
        metric_stats=metric_stats,
        current_thresholds=current_thresholds,
        look_back_days=look_back_days,
    )

    result = await llm_client.complete(
        prompt=prompt,
        system_prompt=_TUNE_SYSTEM_PROMPT,
        timeout_seconds=timeout_seconds,
        command_type="tune_thresholds",
    )

    recommendations = parse_threshold_recommendations(result.text, current_thresholds)

    if audit is not None:
        await audit.append(
            action_type="threshold_tuning",
            source=source,
            description="AI threshold tuning analysis completed.",
            outcome="success",
            details={
                "provider": result.provider,
                "model": result.model_used,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "look_back_days": look_back_days,
                "recommendation_count": len(recommendations),
                "matched_rule": result.matched_rule,
                "recommendations": [
                    {
                        "metric": r.metric,
                        "key_path": r.key_path,
                        "current_value": r.current_value,
                        "recommended_value": r.recommended_value,
                    }
                    for r in recommendations
                ],
            },
        )

    return recommendations


async def handle_tune_thresholds_command(
    *,
    message: InboundMessage,
    db: DatabaseConnection,
    llm_client: LLMClient | None,
    config: dict[str, Any],
    audit: AuditRepository | None = None,
    look_back_days: int = _DEFAULT_LOOK_BACK_DAYS,
    timeout_seconds: float = 60.0,
) -> OutboundMessage:
    """Handle the !tune-thresholds chat command."""
    from system_sentinel.chat.base import OutboundMessage
    from system_sentinel.core.exceptions import LLMUnavailableError

    if llm_client is None:
        return OutboundMessage(
            text=(
                "LLM assistant is not configured. "
                "Configure `llm` and `llm_providers` in config.yaml."
            ),
            reply_to=message,
        )

    try:
        recommendations = await perform_threshold_analysis(
            db=db,
            llm_client=llm_client,
            config=config,
            audit=audit,
            look_back_days=look_back_days,
            source=f"chat:{message.adapter}:{message.user_id}",
            timeout_seconds=timeout_seconds,
        )
    except LLMUnavailableError as exc:
        return OutboundMessage(
            text=f"LLM assistant unavailable: {exc}",
            reply_to=message,
        )

    text = format_recommendations(recommendations, look_back_days)
    return OutboundMessage(
        text=text[:_MAX_REPORT_CHARS],
        reply_to=message,
    )
