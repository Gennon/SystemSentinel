from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage

if TYPE_CHECKING:
    from system_sentinel.chat.router import ChatRouter
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
            "IP Address": ip,
            "Attempts": str(count),
            "Usernames": usernames_str,
            "Window": f"{window} min",
        },
    )


class AlertHandler:
    """Subscribes to alert events on the event bus and forwards them to the ChatRouter."""

    def __init__(self, chat_router: ChatRouter) -> None:
        self._router = chat_router
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

    async def _on_unknown_connection(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Unknown inbound connection: %s → port %s/%s",
            payload.get("src_ip"),
            payload.get("dest_port"),
            payload.get("protocol"),
        )
        msg = _format_unknown_connection(payload)
        await self._router.broadcast(msg)

    async def _on_brute_force(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Brute-force alert from %s — %d attempt(s)",
            payload.get("ip_address"),
            payload.get("attempt_count", 0),
        )
        msg = _format_brute_force(payload)
        await self._router.broadcast(msg)

    async def _on_connection_repeat_threshold(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Repeated unknown connection attempts from %s — %d attempt(s)",
            payload.get("src_ip"),
            payload.get("attempt_count", 0),
        )
        msg = _format_connection_repeat_threshold(payload)
        await self._router.broadcast(msg)

    async def _on_connection_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing daily unknown connection digest")
        msg = _format_connection_daily_digest(payload)
        await self._router.broadcast(msg)
