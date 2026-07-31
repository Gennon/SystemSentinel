"""AI-powered alert explanation command (US-051).

Handles the !explain command: fetches the most recent alert from the audit log,
gathers current system state, and uses the LLM to produce a contextual explanation.
"""

from __future__ import annotations

import json
from time import monotonic
from typing import Any

from system_sentinel.alerts.remediation import runtime_context_summary
from system_sentinel.chat.base import AlertSeverity, InboundMessage, OutboundMessage
from system_sentinel.core.exceptions import LLMUnavailableError


async def handle_explain_command(
    *,
    message: InboundMessage,
    db: Any,
    llm_client: Any,
    audit: Any,
    timeout_seconds: float = 30.0,
) -> OutboundMessage:
    """Handle the !explain command — deliver an AI-powered explanation of a recent alert."""
    if llm_client is None or not llm_client.is_enabled:
        return OutboundMessage(
            text=(
                "LLM assistant is not configured. "
                "Configure `llm` and `llm_providers` in config.yaml."
            ),
            reply_to=message,
        )

    recent_alerts = await _fetch_recent_alerts(db, limit=10)
    if not recent_alerts:
        return OutboundMessage(
            text=(
                "No recent alerts found in the audit log. There is nothing to explain right now."
            ),
            reply_to=message,
        )

    # Use user-supplied context from the message text, or fall back to most recent alert.
    parts = message.text.strip().split(maxsplit=1)
    user_context = parts[1].strip() if len(parts) > 1 else None

    most_recent = recent_alerts[0]
    prompt = _build_prompt(
        most_recent_alert=most_recent,
        recent_alerts=recent_alerts,
        user_context=user_context,
    )
    system_prompt = (
        "You are SystemSentinel's diagnostic assistant. "
        "Explain what triggered the alert, why it matters, its recent history, "
        "and what the user should do next — without requiring SSH access. "
        "Be concise, clear, and actionable."
    )

    started = monotonic()
    try:
        result = await llm_client.complete(
            prompt=prompt,
            system_prompt=system_prompt,
            timeout_seconds=timeout_seconds,
            command_type="explain_alert",
        )
    except LLMUnavailableError as exc:
        return OutboundMessage(
            text=f"LLM assistant unavailable: {exc}",
            reply_to=message,
        )
    except Exception as exc:
        await _record_failure(audit=audit, message=message, reason=str(exc))
        return OutboundMessage(
            text=f"Failed to generate explanation: {exc}",
            reply_to=message,
        )

    elapsed = monotonic() - started
    alert_title = most_recent.get("description") or most_recent.get("source") or "unknown alert"
    text = (
        f"\U0001f50d **AI Explanation** \u2014 {alert_title}\n\n"
        f"{result.text.strip()[:2800]}\n\n"
        f"_Source: {result.provider}/{result.model_used} \u00b7 {elapsed:.1f}s_"
    )

    await _record_success(
        audit=audit,
        message=message,
        alert_title=alert_title,
        provider=result.provider,
        model=result.model_used,
        elapsed_seconds=elapsed,
        matched_rule=result.matched_rule,
    )

    return OutboundMessage(
        title="\U0001f50d AI Alert Explanation",
        text=text,
        severity=AlertSeverity.INFO,
        reply_to=message,
    )


async def _fetch_recent_alerts(db: Any, *, limit: int) -> list[dict[str, Any]]:
    cursor = await db.connection.execute(
        """
        SELECT timestamp, source, description, outcome, details_json
        FROM audit_log
        WHERE action_type = 'alert_fired'
          AND outcome = 'success'
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, limit),),
    )
    rows = await cursor.fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        entry: dict[str, Any] = {
            "timestamp": row[0],
            "source": row[1],
            "description": row[2],
            "outcome": row[3],
        }
        raw_details = row[4]
        if isinstance(raw_details, str):
            try:
                entry["details"] = json.loads(raw_details)
            except json.JSONDecodeError:
                entry["details"] = {}
        else:
            entry["details"] = {}
        result.append(entry)
    return result


def _build_prompt(
    *,
    most_recent_alert: dict[str, Any],
    recent_alerts: list[dict[str, Any]],
    user_context: str | None,
) -> str:
    lines: list[str] = [
        "You are explaining a SystemSentinel alert to a system administrator.",
        "",
        "=== Most Recent Alert ===",
        f"Event type : {most_recent_alert.get('source', 'unknown')}",
        f"Title      : {most_recent_alert.get('description', 'unknown')}",
        f"Fired at   : {most_recent_alert.get('timestamp', 'unknown')}",
    ]
    details = most_recent_alert.get("details", {})
    if isinstance(details, dict):
        severity = details.get("severity", "unknown")
        lines.append(f"Severity   : {severity}")
        suppressed = details.get("chat_notification_suppressed", False)
        if suppressed:
            lines.append("Note: this alert was suppressed from chat at the time it fired.")

    if user_context:
        lines += ["", f"User context: {user_context}"]

    if len(recent_alerts) > 1:
        lines += ["", "=== Recent Alert History (last 10) ==="]
        for alert in recent_alerts[1:]:
            lines.append(
                f"- {alert.get('timestamp', '?')} | {alert.get('source', '?')} | "
                f"{alert.get('description', '?')}"
            )

    lines += [
        "",
        "=== Current System State ===",
        runtime_context_summary(),
        "",
        "Please explain:",
        "1. What triggered this alert and what it means",
        "2. Why it matters and what risk it poses",
        "3. Any pattern from the recent alert history",
        "4. Recommended next steps the administrator can take",
    ]
    return "\n".join(lines)


async def _record_success(
    *,
    audit: Any,
    message: InboundMessage,
    alert_title: str,
    provider: str,
    model: str,
    elapsed_seconds: float,
    matched_rule: dict[str, Any] | None = None,
) -> None:
    if audit is None:
        return
    await audit.append(
        action_type="explain_alert",
        source=f"chat:{message.adapter}:{message.user_id}",
        description=f"AI explanation delivered for alert: {alert_title}.",
        outcome="success",
        details={
            "adapter": message.adapter,
            "channel_id": message.channel_id,
            "user_id": message.user_id,
            "username": message.username,
            "provider": provider,
            "model": model,
            "elapsed_seconds": round(elapsed_seconds, 3),
            "matched_rule": matched_rule,
        },
    )


async def _record_failure(
    *,
    audit: Any,
    message: InboundMessage,
    reason: str,
) -> None:
    if audit is None:
        return
    await audit.append(
        action_type="explain_alert",
        source=f"chat:{message.adapter}:{message.user_id}",
        description="AI explanation failed.",
        outcome="failure",
        details={
            "adapter": message.adapter,
            "channel_id": message.channel_id,
            "user_id": message.user_id,
            "username": message.username,
            "reason": reason,
        },
    )
