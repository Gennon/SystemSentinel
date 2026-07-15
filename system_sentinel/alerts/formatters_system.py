from __future__ import annotations

from typing import Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.chat.digest_builder import DigestBuilder


def _format_old_files_daily_digest(payload: dict[str, Any]) -> OutboundMessage:
    """Build OutboundMessage for the daily old-file summary."""
    rows: list[dict[str, Any]] = payload["rows"]
    period_hours: int = int(payload["period_hours"])

    total_files = sum(int(r["file_count"]) for r in rows)
    total_size_bytes = sum(int(r["total_size_bytes"]) for r in rows)
    lines = [
        f"• {r['watched_directory']}: {r['file_count']} file(s), {r['total_size_bytes']} bytes"
        for r in rows
    ]
    body = "\n".join(lines)
    return OutboundMessage(
        title="📋 Daily Old Files Summary",
        text=body,
        severity=AlertSeverity.INFO,
        fields={
            "Watched Directories": str(len(rows)),
            "Files Found": str(total_files),
            "Total Size (bytes)": str(total_size_bytes),
            "Period": f"Last {period_hours} hours",
        },
    )


def _format_system_daily_digest(payload: dict[str, Any]) -> OutboundMessage:
    generated_at = payload["generated_at"]
    sections_payload = payload["sections"]
    sections = {str(key): str(value) for key, value in sections_payload.items()}
    builder = DigestBuilder()
    return builder.build_daily_digest(
        generated_at=str(generated_at),
        sections=sections,
    )


def _format_cpu_threshold_exceeded(payload: dict[str, Any]) -> OutboundMessage:
    return OutboundMessage(
        title="⚠️ High CPU Usage",
        text=(
            f"CPU alert on **{payload.get('hostname', 'unknown')}**: "
            f"{payload.get('current_value', '—')} (threshold {payload.get('threshold', '—')})."
        ),
        severity=AlertSeverity.WARNING,
        fields={
            "Event Type": str(payload.get("event_type", "cpu_threshold_exceeded")),
            "Current Value": str(payload.get("current_value", "—")),
            "Threshold": str(payload.get("threshold", "—")),
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
        },
    )


def _format_ram_threshold_exceeded(payload: dict[str, Any]) -> OutboundMessage:
    return OutboundMessage(
        title="⚠️ High RAM Usage",
        text=(
            f"RAM alert on **{payload.get('hostname', 'unknown')}**: "
            f"{payload.get('current_value', '—')} (threshold {payload.get('threshold', '—')})."
        ),
        severity=AlertSeverity.WARNING,
        fields={
            "Event Type": str(payload.get("event_type", "ram_threshold_exceeded")),
            "Current Value": str(payload.get("current_value", "—")),
            "Threshold": str(payload.get("threshold", "—")),
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
        },
    )


def _format_disk_threshold_exceeded(payload: dict[str, Any]) -> OutboundMessage:
    mountpoint = str(payload.get("mountpoint", "unknown"))
    device = str(payload.get("device", "unknown"))
    return OutboundMessage(
        title="🔴 Disk Usage Critical",
        text=(
            f"Disk alert on **{payload.get('hostname', 'unknown')}** for "
            f"**{mountpoint}** ({device}): {payload.get('current_value', '—')} "
            f"(threshold {payload.get('threshold', '—')})."
        ),
        severity=AlertSeverity.CRITICAL,
        fields={
            "Event Type": str(payload.get("event_type", "disk_threshold_exceeded")),
            "Current Value": str(payload.get("current_value", "—")),
            "Threshold": str(payload.get("threshold", "—")),
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
            "Mountpoint": mountpoint,
            "Device": device,
        },
    )


def _format_network_threshold_exceeded(payload: dict[str, Any]) -> OutboundMessage:
    bytes_sent = int(payload.get("bytes_sent", 0))
    bytes_recv = int(payload.get("bytes_recv", 0))
    triggered_metrics = payload.get("triggered_metrics", [])
    if isinstance(triggered_metrics, list):
        triggered_str = ", ".join(str(metric) for metric in triggered_metrics) or "—"
    else:
        triggered_str = str(triggered_metrics)
    return OutboundMessage(
        title="⚠️ High Network Throughput",
        text=(
            f"Network alert on **{payload.get('hostname', 'unknown')}**: "
            f"sent={bytes_sent} B, recv={bytes_recv} B "
            f"(threshold {payload.get('threshold', '—')})."
        ),
        severity=AlertSeverity.WARNING,
        fields={
            "Event Type": str(payload.get("event_type", "network_throughput_threshold_exceeded")),
            "Bytes Sent": str(bytes_sent),
            "Bytes Received": str(bytes_recv),
            "Threshold": str(payload.get("threshold", "—")),
            "Triggered Metrics": triggered_str,
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
        },
    )


def _format_gpu_threshold_exceeded(payload: dict[str, Any]) -> OutboundMessage:
    triggered_metrics = payload.get("triggered_metrics", [])
    if isinstance(triggered_metrics, list):
        triggered_str = ", ".join(str(metric) for metric in triggered_metrics) or "—"
    else:
        triggered_str = str(triggered_metrics)
    return OutboundMessage(
        title="⚠️ GPU Threshold Exceeded",
        text=(
            f"GPU alert on **{payload.get('hostname', 'unknown')}**: "
            f"util={payload.get('current_utilization_percent', '—')}, "
            f"temp={payload.get('current_temperature_c', '—')} "
            f"(threshold {payload.get('threshold', '—')})."
        ),
        severity=AlertSeverity.WARNING,
        fields={
            "Event Type": str(payload.get("event_type", "gpu_threshold_exceeded")),
            "Current Utilization": str(payload.get("current_utilization_percent", "—")),
            "Current Temperature": str(payload.get("current_temperature_c", "—")),
            "Threshold": str(payload.get("threshold", "—")),
            "Triggered Metrics": triggered_str,
            "Vendor": str(payload.get("vendor", "—")),
            "Device Count": str(payload.get("device_count", "—")),
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
        },
    )
