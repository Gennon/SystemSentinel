from __future__ import annotations

from typing import Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.chat.digest_builder import DigestBuilder


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


def _format_service_failure_detected(payload: dict[str, Any]) -> OutboundMessage:
    service_name = str(payload.get("service_name", "unknown"))
    status = str(payload.get("status", "unknown"))
    attempt = int(payload.get("attempt", 1))
    max_attempts = int(payload.get("max_attempts", 3))
    journal_lines = str(payload.get("last_journal_lines", "Unavailable."))
    return OutboundMessage(
        title="⚠️ Service Failure Detected",
        text=(
            f"Service **{service_name}** is **{status}**.\n"
            f"Restart attempt {attempt}/{max_attempts} will be attempted.\n\n"
            f"Recent logs:\n```text\n{journal_lines}\n```"
        ),
        severity=AlertSeverity.WARNING,
        fields={
            "Service": service_name,
            "Status": status,
            "Restart Attempt": f"{attempt}/{max_attempts}",
        },
    )


def _format_service_restart_result(payload: dict[str, Any]) -> OutboundMessage:
    service_name = str(payload.get("service_name", "unknown"))
    attempt = int(payload.get("attempt", 1))
    max_attempts = int(payload.get("max_attempts", 3))
    succeeded = bool(payload.get("succeeded", False))
    status_after_restart = str(payload.get("status_after_restart", "unknown"))
    error = str(payload.get("error", "")).strip()
    title = "✅ Service Restart Succeeded" if succeeded else "⚠️ Service Restart Failed"
    text = (
        f"Service **{service_name}** restart attempt {attempt}/{max_attempts} "
        f"{'succeeded' if succeeded else 'failed'}.\n"
        f"Current status: **{status_after_restart}**"
    )
    if error:
        text = f"{text}\nError: {error}"
    return OutboundMessage(
        title=title,
        text=text,
        severity=AlertSeverity.INFO if succeeded else AlertSeverity.WARNING,
        fields={
            "Service": service_name,
            "Attempt": f"{attempt}/{max_attempts}",
            "Status": status_after_restart,
        },
    )


def _format_service_restart_exhausted(payload: dict[str, Any]) -> OutboundMessage:
    service_name = str(payload.get("service_name", "unknown"))
    max_attempts = int(payload.get("max_attempts", 3))
    status_after_restart = str(payload.get("status_after_restart", "unknown"))
    return OutboundMessage(
        title="🚨 Service Restart Attempts Exhausted",
        text=(
            f"Service **{service_name}** did not recover after **{max_attempts}** restart attempts.\n"
            f"Current status: **{status_after_restart}**"
        ),
        severity=AlertSeverity.CRITICAL,
        fields={
            "Service": service_name,
            "Attempts": str(max_attempts),
            "Status": status_after_restart,
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


def _format_brute_force(payload: dict[str, Any]) -> OutboundMessage:
    """Build an OutboundMessage for a brute-force SSH alert payload."""
    ip: str = payload["ip_address"]
    count: int = payload["attempt_count"]
    usernames: list[str] = sorted(payload["usernames"])
    window: int = payload["window_minutes"]

    usernames_str = ", ".join(usernames) if usernames else "—"
    text = (
        f"**{count}** failed SSH login attempt(s) from **{ip}** "
        f"in the last {window} minute(s).\n"
        f"Usernames tried: {usernames_str}"
    )
    return OutboundMessage(
        title="🔴 Brute Force Attack Detected",
        text=text,
        severity=AlertSeverity.CRITICAL,
        fields={
            "Event Type": str(payload.get("event_type", "failed_ssh_logins")),
            "Current Value": str(payload.get("current_value", count)),
            "Threshold": str(payload.get("threshold", "—")),
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
            "IP Address": ip,
            "Attempts": str(count),
            "Usernames": usernames_str,
            "Window": f"{window} min",
        },
    )


def _format_off_hours_login(payload: dict[str, Any]) -> OutboundMessage:
    username = str(payload.get("username", "unknown"))
    ip = str(payload.get("ip_address", "unknown"))
    allowed_hours = str(payload.get("allowed_hours", "07:00-22:00"))
    return OutboundMessage(
        title="⚠️ Off-Hours Login Detected",
        text=(
            f"Successful SSH login by **{username}** from **{ip}** "
            f"outside allowed hours (**{allowed_hours}**)."
        ),
        severity=AlertSeverity.WARNING,
        fields={
            "Anomaly Type": str(payload.get("anomaly_type", "off_hours")),
            "Event Type": str(payload.get("event_type", "successful_ssh_login")),
            "Username": username,
            "IP Address": ip,
            "Auth Method": str(payload.get("auth_method", "unknown")),
            "Port": str(payload.get("port", "—")),
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
            "Allowed Hours": allowed_hours,
        },
    )


def _format_new_user_login(payload: dict[str, Any]) -> OutboundMessage:
    username = str(payload.get("username", "unknown"))
    ip = str(payload.get("ip_address", "unknown"))
    return OutboundMessage(
        title="⚠️ New User Login Detected",
        text=f"First recorded successful SSH login for user **{username}** from **{ip}**.",
        severity=AlertSeverity.WARNING,
        fields={
            "Anomaly Type": str(payload.get("anomaly_type", "new_user")),
            "Event Type": str(payload.get("event_type", "successful_ssh_login")),
            "Username": username,
            "IP Address": ip,
            "Auth Method": str(payload.get("auth_method", "unknown")),
            "Port": str(payload.get("port", "—")),
            "Timestamp": str(payload.get("timestamp", "—")),
            "Hostname": str(payload.get("hostname", "—")),
        },
    )


def _format_impossible_travel(payload: dict[str, Any]) -> OutboundMessage:
    username = str(payload.get("username", "unknown"))
    ip = str(payload.get("ip_address", "unknown"))
    previous_ip = str(payload.get("previous_ip_address", "unknown"))
    distance_km = str(payload.get("distance_km", "—"))
    previous_timestamp = str(payload.get("previous_timestamp", "—"))
    return OutboundMessage(
        title="🚨 Impossible Travel Login Detected",
        text=(
            f"User **{username}** logged in from **{previous_ip}** and **{ip}** "
            f"within a short window (distance ≈ **{distance_km} km**)."
        ),
        severity=AlertSeverity.CRITICAL,
        fields={
            "Anomaly Type": str(payload.get("anomaly_type", "impossible_travel")),
            "Event Type": str(payload.get("event_type", "successful_ssh_login")),
            "Username": username,
            "Current IP": ip,
            "Previous IP": previous_ip,
            "Distance (km)": distance_km,
            "Window (min)": str(payload.get("window_minutes", "—")),
            "Current Timestamp": str(payload.get("timestamp", "—")),
            "Previous Timestamp": previous_timestamp,
            "Hostname": str(payload.get("hostname", "—")),
        },
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


def _format_firewall_drift(payload: dict[str, Any]) -> OutboundMessage:
    backend = str(payload.get("backend", "unknown"))
    missing_rules = payload.get("missing_rules", [])
    unexpected_rules = payload.get("unexpected_rules", [])
    live_policy = str(payload.get("live_default_incoming_policy", "unknown"))
    desired_policy = str(payload.get("desired_default_incoming_policy", "unknown"))
    enforce = bool(payload.get("enforce", False))

    return OutboundMessage(
        title="⚠️ Firewall Drift Detected",
        text=(
            f"Firewall backend **{backend}** is out of sync with desired state.\n"
            f"Missing rules: **{len(missing_rules) if isinstance(missing_rules, list) else 0}**\n"
            f"Unexpected rules: **{len(unexpected_rules) if isinstance(unexpected_rules, list) else 0}**\n"
            f"Default incoming policy: live=**{live_policy}**, desired=**{desired_policy}**\n"
            f"Auto-enforcement: **{'enabled' if enforce else 'disabled'}**"
        ),
        severity=AlertSeverity.WARNING,
        fields={
            "Backend": backend,
            "Missing Rules": str(len(missing_rules) if isinstance(missing_rules, list) else 0),
            "Unexpected Rules": str(
                len(unexpected_rules) if isinstance(unexpected_rules, list) else 0
            ),
            "Live Policy": live_policy,
            "Desired Policy": desired_policy,
            "Enforce": "true" if enforce else "false",
        },
    )
