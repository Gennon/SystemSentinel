from __future__ import annotations

from typing import Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage


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
