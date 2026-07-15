from __future__ import annotations

from typing import Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage


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
