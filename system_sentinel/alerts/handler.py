from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.chat.digest_builder import DigestBuilder

if TYPE_CHECKING:
    from system_sentinel.chat.router import ChatRouter
    from system_sentinel.core.context import AuditRepository
    from system_sentinel.core.event_bus import InProcessEventBus


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

    ports_str = ", ".join(str(p) for p in ports) if ports else "—"
    text = (
        f"**{count}** unknown inbound connection attempt(s) from **{src_ip}** "
        f"in the last {window} minute(s).\n"
        f"Ports targeted: {ports_str}"
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


class AlertHandler:
    """Subscribes to alert events on the event bus and forwards them to the ChatRouter."""

    def __init__(self, chat_router: ChatRouter, audit: AuditRepository | None = None) -> None:
        self._router = chat_router
        self._audit = audit
        self._logger = logging.getLogger("sentinel.alerts.handler")

    def register(self, event_bus: InProcessEventBus) -> None:
        """Wire this handler into *event_bus* by subscribing to known alert events."""
        event_bus.subscribe("alert.login.brute_force_detected", self._on_brute_force)
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

    async def _on_unknown_connection(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Unknown inbound connection: %s → port %s/%s",
            payload.get("src_ip"),
            payload.get("dest_port"),
            payload.get("protocol"),
        )
        msg = _format_unknown_connection(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _on_brute_force(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Brute-force alert from %s — %d attempt(s)",
            payload.get("ip_address"),
            payload.get("attempt_count", 0),
        )
        msg = _format_brute_force(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _on_connection_repeat_threshold(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Repeated unknown connection attempts from %s — %d attempt(s)",
            payload.get("src_ip"),
            payload.get("attempt_count", 0),
        )
        msg = _format_connection_repeat_threshold(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _on_connection_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing daily unknown connection digest")
        msg = _format_connection_daily_digest(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _on_old_files_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing daily old-files digest")
        msg = _format_old_files_daily_digest(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _on_system_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing system daily digest")
        msg = _format_system_daily_digest(payload)
        await self._router.broadcast(msg)

    async def _on_cpu_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("CPU threshold exceeded: %s", payload.get("current_value"))
        msg = _format_cpu_threshold_exceeded(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _on_ram_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("RAM threshold exceeded: %s", payload.get("current_value"))
        msg = _format_ram_threshold_exceeded(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _on_disk_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("Disk threshold exceeded: %s", payload.get("current_value"))
        msg = _format_disk_threshold_exceeded(payload)
        await self._router.broadcast(msg)
        await self._record_alert(event_type, msg)

    async def _record_alert(self, event_type: str, msg: OutboundMessage) -> None:
        if self._audit is None:
            return
        await self._audit.append(
            action_type="alert_fired",
            source=event_type,
            description=msg.title or event_type,
            outcome="success",
            details={"severity": msg.severity.value},
        )
