from __future__ import annotations

import asyncio
import logging
from time import monotonic
from typing import TYPE_CHECKING, Any

import psutil

from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.chat.digest_builder import DigestBuilder
from system_sentinel.core.exceptions import LLMUnavailableError

if TYPE_CHECKING:
    from system_sentinel.chat.router import ChatRouter
    from system_sentinel.core.context import AuditRepository, LLMClient
    from system_sentinel.core.event_bus import InProcessEventBus

_EVENT_SEVERITY_KEYS = {
    "alert.cpu.threshold_exceeded": "cpu",
    "alert.ram.threshold_exceeded": "ram",
    "alert.disk.threshold_exceeded": "disk",
    "alert.network.throughput_threshold_exceeded": "network_throughput",
    "alert.login.brute_force_detected": "login",
    "alert.login.off_hours_detected": "login",
    "alert.login.new_user_detected": "login",
    "alert.login.impossible_travel_detected": "login",
    "alert.connection.unknown_ip_detected": "network_unknown_ip",
    "alert.connection.repeated_attempts_detected": "network_repeat",
    "alert.connection.daily_digest": "network_digest",
    "alert.files.daily_digest": "files_digest",
    "alert.service.failure_detected": "service_failure",
    "alert.service.restart_result": "service_restart_result",
    "alert.service.restart_exhausted": "service_restart_exhausted",
    "alert.firewall.drift_detected": "firewall_drift",
}

_SEVERITY_RANK: dict[AlertSeverity, int] = {
    AlertSeverity.INFO: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.CRITICAL: 2,
}


def _coerce_severity(value: object) -> AlertSeverity | None:
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    if not lowered:
        return None
    try:
        return AlertSeverity(lowered)
    except ValueError:
        return None


def _coerce_positive_float(value: object, *, default: float) -> float:
    if isinstance(value, (int, float)):
        parsed = float(value)
        if parsed > 0:
            return parsed
    return default


def _with_severity(msg: OutboundMessage, severity: AlertSeverity) -> OutboundMessage:
    return OutboundMessage(
        title=msg.title,
        text=msg.text,
        severity=severity,
        fields=msg.fields,
        reply_to=msg.reply_to,
    )


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


class AlertHandler:
    """Subscribes to alert events on the event bus and forwards them to the ChatRouter."""

    def __init__(
        self,
        chat_router: ChatRouter,
        audit: AuditRepository | None = None,
        llm: LLMClient | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._router = chat_router
        self._audit = audit
        self._llm = llm
        self._logger = logging.getLogger("sentinel.alerts.handler")
        self._severity_levels: dict[str, AlertSeverity] = {}
        self._notify_min_severity = AlertSeverity.INFO
        self._llm_remediation_enabled = False
        self._llm_timeout_seconds = 30.0
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._load_config(config or {})

    def _load_config(self, config: dict[str, Any]) -> None:
        self._llm_remediation_enabled = bool(config.get("llm_remediation", False))
        llm_cfg = config.get("llm", {})
        if isinstance(llm_cfg, dict):
            self._llm_timeout_seconds = _coerce_positive_float(
                llm_cfg.get("timeout_seconds"), default=30.0
            )
        self._load_alert_config(config)

    def _load_alert_config(self, config: dict[str, Any]) -> None:
        alerts_cfg = config.get("alerts", {})
        if not isinstance(alerts_cfg, dict):
            return
        raw_levels = alerts_cfg.get("severity_levels", {})
        if isinstance(raw_levels, dict):
            for key, raw_value in raw_levels.items():
                if not isinstance(key, str):
                    continue
                severity = _coerce_severity(raw_value)
                if severity is None:
                    continue
                self._severity_levels[key.strip()] = severity
        min_severity = _coerce_severity(alerts_cfg.get("notify_min_severity"))
        if min_severity is not None:
            self._notify_min_severity = min_severity

    def register(self, event_bus: InProcessEventBus) -> None:
        """Wire this handler into *event_bus* by subscribing to known alert events."""
        event_bus.subscribe("alert.login.brute_force_detected", self._on_brute_force)
        event_bus.subscribe("alert.login.off_hours_detected", self._on_off_hours_login)
        event_bus.subscribe("alert.login.new_user_detected", self._on_new_user_login)
        event_bus.subscribe("alert.login.impossible_travel_detected", self._on_impossible_travel)
        event_bus.subscribe("alert.connection.unknown_ip_detected", self._on_unknown_connection)
        event_bus.subscribe(
            "alert.connection.repeated_attempts_detected",
            self._on_connection_repeat_threshold,
        )
        event_bus.subscribe("alert.connection.daily_digest", self._on_connection_daily_digest)
        event_bus.subscribe("alert.files.daily_digest", self._on_old_files_daily_digest)
        event_bus.subscribe("alert.system.daily_digest", self._on_system_daily_digest)
        event_bus.subscribe("alert.cpu.threshold_exceeded", self._on_cpu_threshold_exceeded)
        event_bus.subscribe("alert.ram.threshold_exceeded", self._on_ram_threshold_exceeded)
        event_bus.subscribe("alert.disk.threshold_exceeded", self._on_disk_threshold_exceeded)
        event_bus.subscribe(
            "alert.network.throughput_threshold_exceeded",
            self._on_network_threshold_exceeded,
        )
        event_bus.subscribe("alert.service.failure_detected", self._on_service_failure_detected)
        event_bus.subscribe("alert.service.restart_result", self._on_service_restart_result)
        event_bus.subscribe("alert.service.restart_exhausted", self._on_service_restart_exhausted)
        event_bus.subscribe("alert.firewall.drift_detected", self._on_firewall_drift)

    async def _on_unknown_connection(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Unknown inbound connection: %s → port %s/%s",
            payload.get("src_ip"),
            payload.get("dest_port"),
            payload.get("protocol"),
        )
        msg = self._apply_severity(event_type, payload, _format_unknown_connection(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_brute_force(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Brute-force alert from %s — %d attempt(s)",
            payload.get("ip_address"),
            payload.get("attempt_count", 0),
        )
        msg = self._apply_severity(event_type, payload, _format_brute_force(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_off_hours_login(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Off-hours login detected: user=%s ip=%s",
            payload.get("username"),
            payload.get("ip_address"),
        )
        msg = self._apply_severity(event_type, payload, _format_off_hours_login(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_new_user_login(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "New user login detected: user=%s ip=%s",
            payload.get("username"),
            payload.get("ip_address"),
        )
        msg = self._apply_severity(event_type, payload, _format_new_user_login(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_impossible_travel(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Impossible travel login detected: user=%s current=%s previous=%s",
            payload.get("username"),
            payload.get("ip_address"),
            payload.get("previous_ip_address"),
        )
        msg = self._apply_severity(event_type, payload, _format_impossible_travel(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_connection_repeat_threshold(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Repeated unknown connection attempts from %s — %d attempt(s)",
            payload.get("src_ip"),
            payload.get("attempt_count", 0),
        )
        msg = self._apply_severity(
            event_type, payload, _format_connection_repeat_threshold(payload)
        )
        await self._notify_and_record(event_type, payload, msg)

    async def _on_connection_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing daily unknown connection digest")
        msg = self._apply_severity(event_type, payload, _format_connection_daily_digest(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_old_files_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing daily old-files digest")
        msg = self._apply_severity(event_type, payload, _format_old_files_daily_digest(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_system_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing system daily digest")
        msg = _format_system_daily_digest(payload)
        await self._router.broadcast(msg)

    async def _on_cpu_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("CPU threshold exceeded: %s", payload.get("current_value"))
        msg = self._apply_severity(event_type, payload, _format_cpu_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_ram_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("RAM threshold exceeded: %s", payload.get("current_value"))
        msg = self._apply_severity(event_type, payload, _format_ram_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_disk_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("Disk threshold exceeded: %s", payload.get("current_value"))
        msg = self._apply_severity(event_type, payload, _format_disk_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_network_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Network throughput threshold exceeded: sent=%s recv=%s",
            payload.get("bytes_sent"),
            payload.get("bytes_recv"),
        )
        msg = self._apply_severity(event_type, payload, _format_network_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_service_failure_detected(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Service failure detected: %s is %s",
            payload.get("service_name"),
            payload.get("status"),
        )
        msg = self._apply_severity(event_type, payload, _format_service_failure_detected(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_service_restart_result(self, event_type: str, payload: Any) -> None:
        succeeded = bool(payload.get("succeeded", False))
        if succeeded:
            self._logger.info("Service restart succeeded: %s", payload.get("service_name"))
        else:
            self._logger.warning("Service restart failed: %s", payload.get("service_name"))
        msg = self._apply_severity(event_type, payload, _format_service_restart_result(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_service_restart_exhausted(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Service restart attempts exhausted: %s",
            payload.get("service_name"),
        )
        msg = self._apply_severity(event_type, payload, _format_service_restart_exhausted(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_firewall_drift(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Firewall drift detected: backend=%s missing=%s unexpected=%s",
            payload.get("backend"),
            len(payload.get("missing_rules", []))
            if isinstance(payload.get("missing_rules"), list)
            else 0,
            len(payload.get("unexpected_rules", []))
            if isinstance(payload.get("unexpected_rules"), list)
            else 0,
        )
        msg = self._apply_severity(event_type, payload, _format_firewall_drift(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _notify_and_record(self, event_type: str, payload: Any, msg: OutboundMessage) -> None:
        suppressed = _SEVERITY_RANK[msg.severity] < _SEVERITY_RANK[self._notify_min_severity]
        if not suppressed:
            await self._router.broadcast(msg)
        await self._record_alert(event_type, msg, suppressed=suppressed)
        if suppressed:
            return
        if msg.severity != AlertSeverity.CRITICAL:
            return
        await self._maybe_send_llm_remediation(event_type=event_type, payload=payload, alert=msg)

    def _apply_severity(
        self, event_type: str, payload: Any, msg: OutboundMessage
    ) -> OutboundMessage:
        override = None
        if isinstance(payload, dict):
            override = _coerce_severity(payload.get("severity_override"))
            if override is None:
                override = _coerce_severity(payload.get("rule_severity"))
        if override is not None:
            return _with_severity(msg, override)

        configured = self._severity_levels.get(event_type)
        if configured is None:
            alias = _EVENT_SEVERITY_KEYS.get(event_type)
            if alias is not None:
                configured = self._severity_levels.get(alias)
        if configured is None and isinstance(payload, dict):
            configured = _coerce_severity(payload.get("severity"))
        if configured is None:
            return msg
        return _with_severity(msg, configured)

    async def _record_alert(
        self,
        event_type: str,
        msg: OutboundMessage,
        *,
        suppressed: bool = False,
    ) -> None:
        if self._audit is None:
            return
        await self._audit.append(
            action_type="alert_fired",
            source=event_type,
            description=msg.title or event_type,
            outcome="success",
            details={
                "severity": msg.severity.value,
                "chat_notification_suppressed": suppressed,
            },
        )

    async def _maybe_send_llm_remediation(
        self,
        *,
        event_type: str,
        payload: Any,
        alert: OutboundMessage,
    ) -> None:
        llm_client = self._llm
        if not self._llm_remediation_enabled:
            return
        if llm_client is None or not llm_client.is_enabled:
            return

        system_prompt = (
            "You are SystemSentinel's remediation assistant. "
            "Provide concise, low-risk, actionable remediation steps. "
            "Do not suggest automatic execution and avoid destructive actions unless explicitly justified."
        )
        prompt = self._build_remediation_prompt(event_type=event_type, payload=payload, alert=alert)
        started = monotonic()
        request_task = asyncio.create_task(
            llm_client.complete(
                prompt=prompt,
                system_prompt=system_prompt,
                timeout_seconds=self._llm_timeout_seconds,
            )
        )
        try:
            result = await asyncio.wait_for(asyncio.shield(request_task), timeout=15.0)
        except TimeoutError:
            follow_up = asyncio.create_task(
                self._publish_delayed_remediation(
                    request_task=request_task,
                    event_type=event_type,
                    alert=alert,
                    started=started,
                )
            )
            self._track_background_task(follow_up)
            return
        except LLMUnavailableError as exc:
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return
        except Exception as exc:
            self._logger.warning(
                "LLM remediation generation failed for %s: %s",
                event_type,
                exc,
            )
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return

        await self._publish_llm_remediation_message(
            event_type=event_type,
            alert=alert,
            suggestion=result.text,
            provider=result.provider,
            model=result.model_used,
            elapsed_seconds=monotonic() - started,
            delayed=False,
        )

    async def _publish_delayed_remediation(
        self,
        *,
        request_task: asyncio.Task[Any],
        event_type: str,
        alert: OutboundMessage,
        started: float,
    ) -> None:
        try:
            result = await request_task
        except LLMUnavailableError as exc:
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return
        except Exception as exc:
            self._logger.warning(
                "Delayed LLM remediation generation failed for %s: %s",
                event_type,
                exc,
            )
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return

        await self._publish_llm_remediation_message(
            event_type=event_type,
            alert=alert,
            suggestion=result.text,
            provider=result.provider,
            model=result.model_used,
            elapsed_seconds=monotonic() - started,
            delayed=True,
        )

    async def _publish_llm_remediation_message(
        self,
        *,
        event_type: str,
        alert: OutboundMessage,
        suggestion: str,
        provider: str,
        model: str,
        elapsed_seconds: float,
        delayed: bool,
    ) -> None:
        clean_suggestion = suggestion.strip()
        if not clean_suggestion:
            await self._record_llm_remediation_failure(
                event_type=event_type, reason="LLM returned an empty remediation suggestion."
            )
            return

        elapsed_display = f"{elapsed_seconds:.1f}s"
        follow_up_title = "🤖 AI remediation suggestion"
        if delayed:
            follow_up_title = "🤖 AI remediation suggestion (delayed)"
        alert_title = alert.title or event_type
        text = (
            f"Follow-up for **{alert_title}**.\n\n"
            "Advisory only — no automatic action has been taken.\n\n"
            f"{clean_suggestion[:2800]}\n\n"
            f"_Source: {provider}/{model} · generated in {elapsed_display}_"
        )
        await self._router.broadcast(
            OutboundMessage(
                title=follow_up_title,
                text=text,
                severity=AlertSeverity.INFO,
            )
        )
        await self._record_llm_remediation_success(
            event_type=event_type,
            provider=provider,
            model=model,
            delayed=delayed,
            elapsed_seconds=elapsed_seconds,
            alert_title=alert_title,
        )

    def _build_remediation_prompt(
        self, *, event_type: str, payload: Any, alert: OutboundMessage
    ) -> str:
        lines = [
            "You are generating remediation advice for a critical SystemSentinel alert.",
            "",
            f"Alert event type: {event_type}",
            f"Alert title: {alert.title or event_type}",
            f"Alert body: {alert.text}",
            "",
            "Alert metrics/details:",
        ]
        fields = alert.fields or {}
        if fields:
            for key, value in fields.items():
                lines.append(f"- {key}: {value}")
        elif isinstance(payload, dict):
            for key, value in payload.items():
                lines.append(f"- {key}: {value}")
        else:
            lines.append("- No structured fields available.")
        lines.extend(
            [
                "",
                "Recent system context:",
                self._runtime_context_summary(),
                "",
                "Return concise, step-by-step remediation guidance with explicit verification steps.",
            ]
        )
        return "\n".join(lines)

    def _runtime_context_summary(self) -> str:
        lines: list[str] = []
        try:
            lines.append(f"- CPU percent: {psutil.cpu_percent(interval=None):.1f}")
        except psutil.Error:
            lines.append("- CPU percent: unavailable")
        try:
            lines.append(f"- RAM percent: {psutil.virtual_memory().percent:.1f}")
        except psutil.Error:
            lines.append("- RAM percent: unavailable")
        try:
            lines.append(f"- Disk percent (/): {psutil.disk_usage('/').percent:.1f}")
        except (psutil.Error, OSError):
            lines.append("- Disk percent (/): unavailable")
        try:
            load_1, load_5, load_15 = psutil.getloadavg()
            lines.append(f"- Load average: {load_1:.2f}, {load_5:.2f}, {load_15:.2f}")
        except (OSError, AttributeError):
            lines.append("- Load average: unavailable")
        return "\n".join(lines)

    async def _record_llm_remediation_success(
        self,
        *,
        event_type: str,
        provider: str,
        model: str,
        delayed: bool,
        elapsed_seconds: float,
        alert_title: str,
    ) -> None:
        if self._audit is None:
            return
        await self._audit.append(
            action_type="llm_remediation",
            source=event_type,
            description=f"Published AI remediation suggestion for {alert_title}.",
            outcome="success",
            details={
                "provider": provider,
                "model": model,
                "delayed_follow_up": delayed,
                "elapsed_seconds": round(elapsed_seconds, 3),
            },
        )

    async def _record_llm_remediation_failure(self, *, event_type: str, reason: str) -> None:
        if self._audit is None:
            return
        await self._audit.append(
            action_type="llm_remediation",
            source=event_type,
            description="Failed to generate AI remediation suggestion.",
            outcome="failure",
            details={"reason": reason},
        )

    def _track_background_task(self, task: asyncio.Task[None]) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
