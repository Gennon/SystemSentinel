from __future__ import annotations

from typing import Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage


def _format_unknown_connection(payload: dict[str, Any]) -> OutboundMessage:
    """Build an OutboundMessage for an unknown inbound connection alert payload."""
    src_ip: str = payload["src_ip"]
    dest_port: int = payload["dest_port"]
    protocol: str = payload["protocol"]
    timestamp: str = payload["timestamp"]

    text = (
        f"Inbound connection from unknown IP **{src_ip}** "
        f"to port **{dest_port}/{protocol}** at {timestamp}."
    )
    return OutboundMessage(
        title="⚠️ Unknown Inbound Connection",
        text=text,
        severity=AlertSeverity.WARNING,
        fields={
            "Source IP": src_ip,
            "Destination Port": str(dest_port),
            "Protocol": protocol,
            "Timestamp": timestamp,
        },
    )


def _format_connection_repeat_threshold(payload: dict[str, Any]) -> OutboundMessage:
    """Build OutboundMessage for repeated connection attempts from one source IP."""
    src_ip: str = payload["src_ip"]
    count: int = payload["attempt_count"]
    window: int = payload["window_minutes"]
    ports: list[int] = sorted(payload.get("ports", []))
    timestamp: str = payload["timestamp"]
    classification = payload.get("classification", {})
    category = str(classification.get("category", "unclassified"))
    confidence = classification.get("confidence")
    recommended_action = str(classification.get("recommended_action", "watch"))
    reasons = classification.get("reasons", [])
    reasons_str = (
        ", ".join(str(reason) for reason in reasons)
        if isinstance(reasons, list) and reasons
        else "no specific reasons"
    )

    ports_str = ", ".join(str(p) for p in ports) if ports else "—"
    confidence_text = f"{float(confidence):.2f}" if isinstance(confidence, (float, int)) else "n/a"
    text = (
        f"**{count}** unknown inbound connection attempt(s) from **{src_ip}** "
        f"in the last {window} minute(s).\n"
        f"Ports targeted: {ports_str}\n"
        f"Classification: **{category}** (confidence {confidence_text}).\n"
        f"Recommended action: **{recommended_action}**.\n"
        f"Reasons: {reasons_str}"
    )
    return OutboundMessage(
        title="🚨 Repeated Unknown Connection Attempts",
        text=text,
        severity=AlertSeverity.CRITICAL,
        fields={
            "Source IP": src_ip,
            "Attempts": str(count),
            "Window": f"{window} min",
            "Ports": ports_str,
            "Classification": category,
            "Confidence": confidence_text,
            "Recommended Action": recommended_action,
            "Reasons": reasons_str,
            "Timestamp": timestamp,
        },
    )


def _format_connection_daily_digest(payload: dict[str, Any]) -> OutboundMessage:
    """Build OutboundMessage for the daily connection-attempt digest."""
    rows: list[dict[str, Any]] = payload["rows"]
    period_hours: int = int(payload["period_hours"])

    total_attempts = sum(int(r["attempts"]) for r in rows)
    unique_ips = len({str(r["ip_address"]) for r in rows})
    unique_ports = len({int(r["dest_port"]) for r in rows})

    lines = [
        f"• {r['ip_address']} → port {r['dest_port']}: {r['attempts']} attempt(s)" for r in rows
    ]
    body = "\n".join(lines)
    return OutboundMessage(
        title="📋 Daily Unknown Connection Summary",
        text=body,
        severity=AlertSeverity.WARNING,
        fields={
            "Unique IPs": str(unique_ips),
            "Unique Ports": str(unique_ports),
            "Total Attempts": str(total_attempts),
            "Period": f"Last {period_hours} hours",
        },
    )
