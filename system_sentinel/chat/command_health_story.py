"""AI narrative health report command (US-050).

Gathers metric trends, security posture, service stability and notable events
over a configurable look-back window, then asks the LLM to write a plain-English
narrative summary of the system's health trajectory.

Delivered via chat and written to the audit log.  Can also be triggered on demand
via the ``!health-story`` chat command.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from typing import TYPE_CHECKING, Any

import psutil

if TYPE_CHECKING:
    from system_sentinel.chat.base import InboundMessage, OutboundMessage
    from system_sentinel.core.context import AuditRepository, LLMClient
    from system_sentinel.db.audit_repository import SqliteAuditRepository
    from system_sentinel.db.connection import DatabaseConnection
    from system_sentinel.db.metrics_repository import MetricsRepository


_NARRATIVE_SYSTEM_PROMPT = (
    "You are SystemSentinel, a Linux system management assistant. "
    "You have been given trend data and notable events covering a recent time window. "
    "Write a concise, plain-English narrative health summary (3-6 paragraphs) that: "
    "1) describes resource trends (not just raw numbers -- interpret direction and magnitude), "
    "2) comments on security posture changes since the last period, "
    "3) covers service stability and any downtime events, "
    "4) highlights the most notable events or anomalies. "
    "Use a direct, professional tone. If everything is healthy, say so clearly. "
    "Where concerning trends exist, explain likely causes and recommend actions."
)

_MAX_REPORT_CHARS = 3000


def _avg(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _trend_label(early: float | None, late: float | None) -> str:
    """Return a human-readable trend direction."""
    if early is None or late is None:
        return "no data"
    delta = late - early
    if abs(delta) < 1.0:
        return "stable"
    direction = "up" if delta > 0 else "down"
    return f"{direction} {abs(delta):.1f}%"


async def gather_narrative_context(
    *,
    metrics_repo: MetricsRepository,
    audit_repo: SqliteAuditRepository,
    look_back_days: int = 7,
) -> dict[str, Any]:
    """Collect trend data and notable events for the narrative report."""
    now = datetime.now(UTC)
    window_start = now - timedelta(days=look_back_days)
    midpoint = window_start + timedelta(days=look_back_days / 2)

    ctx: dict[str, Any] = {
        "generated_at": now.isoformat(),
        "look_back_days": look_back_days,
    }

    # --- Resource trends (split window in half to detect direction) ---
    resource_trends: dict[str, Any] = {}
    for metric in ("cpu", "ram", "disk"):
        early_rows = await metrics_repo.query_range(metric, since=window_start, until=midpoint)
        late_rows = await metrics_repo.query_range(metric, since=midpoint, until=now)

        key_map: dict[str, str | None] = {
            "cpu": "overall_percent",
            "ram": "percent",
            "disk": None,
        }
        key = key_map[metric]

        def _extract(rows: list[dict[str, Any]], k: str | None) -> list[float]:
            out: list[float] = []
            for r in rows:
                if k is not None:
                    raw = r.get(k)
                    if raw is not None:
                        out.append(float(raw))
                else:
                    # disk: average across partitions
                    parts = r.get("partitions", [])
                    if isinstance(parts, list):
                        vals = [float(p["percent"]) for p in parts if "percent" in p]
                        if vals:
                            out.append(sum(vals) / len(vals))
            return out

        early_vals = _extract(early_rows, key)
        late_vals = _extract(late_rows, key)
        early_avg = _avg(early_vals)
        late_avg = _avg(late_vals)
        resource_trends[metric] = {
            "early_avg": round(early_avg, 1) if early_avg is not None else None,
            "late_avg": round(late_avg, 1) if late_avg is not None else None,
            "trend": _trend_label(early_avg, late_avg),
            "sample_count": len(early_rows) + len(late_rows),
        }
    ctx["resource_trends"] = resource_trends

    # --- Current snapshot ---
    cpu_now = psutil.cpu_percent(interval=None)
    ram_now = psutil.virtual_memory()
    disk_now = psutil.disk_usage("/")
    ctx["current_resources"] = {
        "cpu_percent": cpu_now,
        "ram_percent": ram_now.percent,
        "disk_percent": disk_now.percent,
    }

    # --- Security posture: latest hardening audit ---
    hardening_row = await audit_repo.latest_hardening_audit()
    if hardening_row is not None:
        details_raw = hardening_row.get("details_json")
        checks: list[dict[str, Any]] = []
        if isinstance(details_raw, str):
            try:
                parsed = json.loads(details_raw)
                if isinstance(parsed, dict) and isinstance(parsed.get("checks"), list):
                    checks = [c for c in parsed["checks"] if isinstance(c, dict)]
            except json.JSONDecodeError:
                pass
        failed = [c for c in checks if str(c.get("status", "")).lower() != "pass"]
        ctx["hardening"] = {
            "timestamp": hardening_row["timestamp"],
            "outcome": hardening_row["outcome"],
            "total_checks": len(checks),
            "failed_count": len(failed),
            "failed_titles": [c.get("title", "?") for c in failed[:5]],
        }
    else:
        ctx["hardening"] = None

    # --- Service stability: recent service_health events ---
    service_rows = await audit_repo.recent_by_type("service_health", 20)
    ctx["service_events"] = [
        {
            "timestamp": str(r["timestamp"]),
            "description": str(r["description"]),
            "outcome": str(r["outcome"]),
        }
        for r in service_rows
    ]

    # --- Notable events: alerts fired in window ---
    alert_rows = await audit_repo.recent_by_type("alert_fired", 20, since=window_start)
    notable_alerts: list[dict[str, str]] = []
    for row in alert_rows:
        severity = "unknown"
        raw_dj = row.get("details_json")
        if isinstance(raw_dj, str):
            try:
                dj = json.loads(raw_dj)
                if isinstance(dj, dict):
                    s = dj.get("severity")
                    if isinstance(s, str) and s.strip():
                        severity = s.strip()
            except json.JSONDecodeError:
                pass
        notable_alerts.append(
            {
                "timestamp": str(row["timestamp"]),
                "description": str(row["description"]),
                "severity": severity,
            }
        )
    ctx["notable_alerts"] = notable_alerts

    return ctx


def build_narrative_prompt(context: dict[str, Any]) -> str:
    """Build the LLM prompt from gathered narrative context."""
    look_back = context.get("look_back_days", 7)
    generated_at = context.get("generated_at", datetime.now(UTC).isoformat())
    lines: list[str] = [
        f"System health narrative report -- generated at {generated_at}",
        f"Look-back window: {look_back} day(s)",
        "",
        "=== RESOURCE TRENDS ===",
    ]

    trends = context.get("resource_trends", {})
    for metric, data in trends.items():
        early = data.get("early_avg")
        late = data.get("late_avg")
        trend = data.get("trend", "no data")
        samples = data.get("sample_count", 0)
        lines.append(
            f"{metric.upper()}: early-avg={early}%  late-avg={late}%  "
            f"trend={trend}  samples={samples}"
        )

    cur = context.get("current_resources", {})
    lines += [
        "",
        "Current snapshot (at report time):",
        f"  CPU={cur.get('cpu_percent', 'n/a')}%  "
        f"RAM={cur.get('ram_percent', 'n/a')}%  "
        f"Disk(/)={cur.get('disk_percent', 'n/a')}%",
    ]

    lines += ["", "=== SECURITY POSTURE ==="]
    hardening = context.get("hardening")
    if hardening:
        lines.append(
            f"Last hardening audit: {hardening['timestamp']} | outcome={hardening['outcome']}"
        )
        lines.append(
            f"Checks: {hardening['total_checks']} total, {hardening['failed_count']} failed"
        )
        if hardening["failed_titles"]:
            lines.append("Failed checks: " + ", ".join(hardening["failed_titles"]))
    else:
        lines.append("No hardening audit data available.")

    lines += ["", "=== SERVICE STABILITY ==="]
    services = context.get("service_events", [])
    if services:
        for s in services[:10]:
            lines.append(f"  {s['timestamp']} | {s['outcome']} | {s['description']}")
    else:
        lines.append("No service health events recorded in the window.")

    lines += ["", f"=== NOTABLE EVENTS (last {look_back}d) ==="]
    alerts = context.get("notable_alerts", [])
    if alerts:
        for a in alerts[:15]:
            lines.append(f"  {a['timestamp']} | {a['severity'].upper()} | {a['description']}")
    else:
        lines.append("No alerts fired in this window.")

    lines += [
        "",
        "Based on all of the above, write a plain-English narrative health summary "
        "covering: resource trends, security posture, service stability, and notable events.",
    ]

    return "\n".join(lines)


def _make_repos(
    db: DatabaseConnection,
) -> tuple[MetricsRepository, SqliteAuditRepository]:
    from system_sentinel.db.audit_repository import SqliteAuditRepository
    from system_sentinel.db.metrics_repository import MetricsRepository

    return MetricsRepository(db), SqliteAuditRepository(db)


async def perform_health_story(
    *,
    db: DatabaseConnection,
    llm_client: LLMClient,
    audit: AuditRepository | None = None,
    look_back_days: int = 7,
    source: str = "chat",
    timeout_seconds: float = 60.0,
) -> str:
    """Generate the narrative health report and return the text."""
    metrics_repo, audit_repo = _make_repos(db)

    context = await gather_narrative_context(
        metrics_repo=metrics_repo,
        audit_repo=audit_repo,
        look_back_days=look_back_days,
    )
    prompt = build_narrative_prompt(context)

    result = await llm_client.complete(
        prompt=prompt,
        system_prompt=_NARRATIVE_SYSTEM_PROMPT,
        timeout_seconds=timeout_seconds,
    )

    report: str = str(result.text).strip()

    if audit is not None:
        await audit.append(
            action_type="narrative_health_report",
            source=source,
            description=f"AI narrative health report generated (look_back={look_back_days}d).",
            outcome="success",
            details={
                "provider": result.provider,
                "model": result.model_used,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "look_back_days": look_back_days,
                "alert_count": len(context.get("notable_alerts", [])),
                "service_event_count": len(context.get("service_events", [])),
                "resource_trends": context.get("resource_trends", {}),
            },
        )

    return report


async def handle_health_story_command(
    *,
    message: InboundMessage,
    db: DatabaseConnection,
    llm_client: LLMClient | None,
    audit: AuditRepository | None = None,
    look_back_days: int = 7,
    timeout_seconds: float = 60.0,
) -> OutboundMessage:
    """Handle the ``!health-story`` chat command."""
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
        report = await perform_health_story(
            db=db,
            llm_client=llm_client,
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

    return OutboundMessage(
        text=f"Health Story (last {look_back_days}d)\n\n{report[:_MAX_REPORT_CHARS]}",
        reply_to=message,
    )
