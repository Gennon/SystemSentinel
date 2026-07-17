from __future__ import annotations

import json
from typing import Any

from system_sentinel.alerts.quiet_hours import parse_quiet_hours_window


def build_status_text(
    *,
    config: dict[str, Any],
    monitor_count: int,
    tool_count: int,
    llm_client: Any,
    psutil_module: Any,
) -> str:
    cpu = psutil_module.cpu_percent(interval=None)
    ram = psutil_module.virtual_memory()
    disk = psutil_module.disk_usage("/")
    uptime_seconds = int(
        (
            datetime_now_utc(psutil_module)
            - from_timestamp_utc(psutil_module.boot_time(), psutil_module)
        ).total_seconds()
    )
    adapters_count = len(config.get("chat_adapters", {}))
    text = (
        f"CPU {cpu:.1f}% | RAM {ram.percent:.1f}% | Disk {disk.percent:.1f}%\n"
        f"Uptime {uptime_seconds}s\n"
        f"Service health: daemon=running, adapters={adapters_count}, "
        f"monitors={monitor_count}, tools={tool_count}"
    )
    alerts_cfg = config.get("alerts", {})
    quiet_hours = (
        parse_quiet_hours_window(alerts_cfg.get("quiet_hours"))
        if isinstance(alerts_cfg, dict)
        else None
    )
    if quiet_hours is None:
        quiet_hours = parse_quiet_hours_window(config.get("quiet_hours"))
    if quiet_hours is None:
        quiet_status = "disabled"
    else:
        state = (
            "active now"
            if quiet_hours.is_active(datetime_now_utc(psutil_module))
            else "inactive now"
        )
        quiet_status = f"{quiet_hours.label} ({state})"
    text = f"{text}\nQuiet hours: {quiet_status}"
    if llm_client is not None and llm_client.is_enabled:
        provider = llm_client.active_provider_name or "unknown"
        return f"{text}\nLLM: enabled ({provider})"
    return f"{text}\nLLM: disabled"


async def build_llm_context_summary(
    *,
    db: Any,
    psutil_module: Any,
    active_alerts: list[str],
) -> str:
    cpu = psutil_module.cpu_percent(interval=None)
    ram = psutil_module.virtual_memory().percent
    disk = psutil_module.disk_usage("/").percent
    recent_alerts = await recent_alerts_for_llm(db=db, limit=5)
    top_processes = await latest_top_processes_for_llm(db=db, limit=5)
    lines = [
        f"CPU percent: {cpu:.1f}",
        f"RAM percent: {ram:.1f}",
        f"Disk percent: {disk:.1f}",
    ]
    if active_alerts:
        lines.append("Active alerts:")
        lines.extend(active_alerts[:8])
    else:
        lines.append("Active alerts: none")
    if recent_alerts:
        lines.append("Recent alerts:")
        lines.extend(recent_alerts)
    else:
        lines.append("Recent alerts: none")
    if top_processes:
        lines.append("Top processes by CPU (latest sample):")
        lines.extend(top_processes)
    else:
        lines.append("Top processes by CPU (latest sample): unavailable")
    return "\n".join(lines)


def extract_prompt_after_command(text: str) -> str | None:
    parts = text.strip().split(maxsplit=1)
    if len(parts) < 2:
        return None
    prompt = parts[1].strip()
    return prompt or None


async def recent_alerts_for_llm(*, db: Any, limit: int) -> list[str]:
    cursor = await db.connection.execute(
        """
        SELECT timestamp, source, description, details_json
        FROM audit_log
        WHERE action_type = 'alert_fired'
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, limit),),
    )
    rows = await cursor.fetchall()
    alerts: list[str] = []
    for row in rows:
        severity = "unknown"
        details_raw = row[3]
        if isinstance(details_raw, str):
            try:
                details = json.loads(details_raw)
            except json.JSONDecodeError:
                details = {}
            if isinstance(details, dict):
                severity_raw = details.get("severity")
                if isinstance(severity_raw, str) and severity_raw.strip():
                    severity = severity_raw.strip()
        alerts.append(f"- {row[0]} | {row[1]} | {severity} | {row[2]}")
    return alerts


async def latest_top_processes_for_llm(*, db: Any, limit: int) -> list[str]:
    cursor = await db.connection.execute(
        """
        SELECT data_json
        FROM system_metrics
        WHERE metric_type = 'cpu'
        ORDER BY id DESC
        LIMIT 1
        """
    )
    row = await cursor.fetchone()
    if row is None:
        return []

    data_raw = row[0]
    if not isinstance(data_raw, str):
        return []
    try:
        data = json.loads(data_raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    top_processes = data.get("top_processes")
    if not isinstance(top_processes, list):
        return []

    lines: list[str] = []
    for process in top_processes[: max(1, limit)]:
        if not isinstance(process, dict):
            continue
        name = str(process.get("name", "unknown"))
        pid = process.get("pid")
        cpu_percent = float(process.get("cpu_percent", 0.0))
        ram_bytes = int(process.get("ram_bytes", 0))
        lines.append(f"- {name} (pid={pid}, cpu={cpu_percent:.1f}%, ram={ram_bytes} bytes)")
    return lines


def datetime_now_utc(psutil_module: Any) -> Any:
    _ = psutil_module
    from datetime import UTC, datetime

    return datetime.now(UTC)


def from_timestamp_utc(value: float, psutil_module: Any) -> Any:
    _ = psutil_module
    from datetime import UTC, datetime

    return datetime.fromtimestamp(value, tz=UTC)
