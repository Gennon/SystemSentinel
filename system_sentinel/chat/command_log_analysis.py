"""AI log analysis command (US-047).

Reads sentinel audit log entries over a configurable look-back window, redacts
sensitive content, and sends the data to the LLM for analysis. The LLM identifies
recurring errors, warnings, and anomalous patterns, then returns concrete
improvement suggestions (config changes, tool fixes, threshold adjustments).
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.chat.base import InboundMessage, OutboundMessage
    from system_sentinel.core.context import AuditRepository, LLMClient
    from system_sentinel.db.audit_repository import SqliteAuditRepository
    from system_sentinel.db.connection import DatabaseConnection

_LOG_ANALYSIS_SYSTEM_PROMPT = (
    "You are SystemSentinel, a Linux system management assistant. "
    "You have been given a structured summary of sentinel's own audit log entries "
    "covering recent operation. "
    "Analyze the patterns, identify recurring errors, warnings, and anomalies in the "
    "sentinel's own operation, and produce a prioritized list of concrete improvement "
    "suggestions (config changes, tool fixes, threshold adjustments, etc.). "
    "Format your response as a numbered list, each item on its own line, "
    "starting with a severity tag: [CRITICAL], [WARNING], or [INFO]. "
    "Be concise and actionable. If the logs look healthy, say so clearly."
)

_MAX_REPORT_CHARS = 3000
_MAX_LOG_ENTRIES = 300

# Patterns for sensitive content that must be redacted before sending to the LLM.
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # key=value style (e.g. password=hunter2, api_key="abc", token: xyz)
    (
        re.compile(
            r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key"
            r"|auth[_-]?token|bearer|credential|access[_-]?key|session[_-]?id)"
            r'([=:\s]+)["\']?([^\s"\'&,;}\]]{3,})["\']?',
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED]",
    ),
    # AWS-style access key IDs
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"), "[REDACTED_AWS_KEY]"),
    # PEM private key blocks
    (
        re.compile(
            r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # Generic long hex strings (32+ chars) that look like secrets
    (
        re.compile(r"\b[0-9a-fA-F]{32,}\b"),
        "[REDACTED_HEX]",
    ),
]


def redact_sensitive_content(text: str) -> str:
    """Replace passwords, keys, and secrets in *text* before sending to an LLM."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


async def gather_log_analysis_context(
    *,
    audit_repo: SqliteAuditRepository,
    look_back_days: int = 7,
) -> dict[str, Any]:
    """Collect and summarize audit log entries for the look-back window."""
    since = datetime.now(UTC) - timedelta(days=look_back_days)
    entries = await audit_repo.recent_since(since=since, limit=_MAX_LOG_ENTRIES)

    total = len(entries)
    failures: list[dict[str, str]] = []
    outcome_counts: Counter[str] = Counter()
    action_type_counts: Counter[str] = Counter()
    failure_action_types: Counter[str] = Counter()

    for row in entries:
        outcome = str(row.get("outcome", ""))
        action_type = str(row.get("action_type", ""))
        outcome_counts[outcome] += 1
        action_type_counts[action_type] += 1

        if outcome in {"failure", "error"}:
            failure_action_types[action_type] += 1
            failures.append(
                {
                    "timestamp": str(row.get("timestamp", "")),
                    "action_type": action_type,
                    "source": str(row.get("source", "")),
                    "description": redact_sensitive_content(str(row.get("description", ""))),
                    "outcome": outcome,
                }
            )

    return {
        "look_back_days": look_back_days,
        "since": since.isoformat(),
        "total_entries": total,
        "outcome_counts": dict(outcome_counts),
        "action_type_counts": dict(action_type_counts),
        "failure_action_types": dict(failure_action_types),
        "failures": failures[:50],  # cap at 50 for prompt size
    }


def build_log_analysis_prompt(context: dict[str, Any]) -> str:
    """Build the LLM prompt from the gathered log analysis context."""
    lines: list[str] = [
        f"Sentinel log analysis — look-back window: {context['look_back_days']} days "
        f"(since {context['since']})",
        f"Total audit entries analysed: {context['total_entries']}",
        "",
        "=== OUTCOME SUMMARY ===",
    ]

    outcome_counts: dict[str, int] = context.get("outcome_counts", {})
    if outcome_counts:
        for outcome, count in sorted(outcome_counts.items(), key=lambda t: -t[1]):
            lines.append(f"  {outcome}: {count}")
    else:
        lines.append("  (no entries)")

    lines.append("")
    lines.append("=== ACTION TYPE BREAKDOWN ===")
    action_type_counts: dict[str, int] = context.get("action_type_counts", {})
    if action_type_counts:
        for action_type, count in sorted(action_type_counts.items(), key=lambda t: -t[1]):
            lines.append(f"  {action_type}: {count}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("=== FAILURE / ERROR ENTRIES ===")
    failures: list[dict[str, str]] = context.get("failures", [])
    failure_action_types: dict[str, int] = context.get("failure_action_types", {})
    if failure_action_types:
        lines.append("Recurring failure types:")
        for action_type, count in sorted(failure_action_types.items(), key=lambda t: -t[1]):
            lines.append(f"  {action_type}: {count} failure(s)")
        lines.append("")

    if failures:
        lines.append("Individual failures (most recent first, capped at 50):")
        for f in failures:
            lines.append(
                f"  [{f['timestamp']}] {f['action_type']} | {f['outcome']} | "
                f"source={f['source']} | {f['description']}"
            )
    else:
        lines.append("  No failures or errors recorded in this period.")

    lines.append("")
    lines.append(
        "Based on the above sentinel audit log data, identify recurring errors, warnings, "
        "and anomalous patterns. Provide a prioritized list of concrete improvement suggestions "
        "(config changes, tool fixes, threshold adjustments). Each item must start with "
        "[CRITICAL], [WARNING], or [INFO]."
    )

    return "\n".join(lines)


async def perform_log_analysis(
    *,
    db: DatabaseConnection,
    llm_client: LLMClient,
    audit: AuditRepository | None = None,
    look_back_days: int = 7,
    source: str = "chat",
    timeout_seconds: float = 60.0,
) -> str:
    """Run log analysis and return the synthesized LLM report."""
    from system_sentinel.db.audit_repository import SqliteAuditRepository

    audit_repo = SqliteAuditRepository(db)
    context = await gather_log_analysis_context(
        audit_repo=audit_repo,
        look_back_days=look_back_days,
    )
    prompt = build_log_analysis_prompt(context)

    result = await llm_client.complete(
        prompt=prompt,
        system_prompt=_LOG_ANALYSIS_SYSTEM_PROMPT,
        timeout_seconds=timeout_seconds,
    )

    report: str = str(result.text).strip()

    if audit is not None:
        await audit.append(
            action_type="log_analysis",
            source=source,
            description="AI log analysis completed.",
            outcome="success",
            details={
                "provider": result.provider,
                "model": result.model_used,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "look_back_days": look_back_days,
                "total_entries_analysed": context.get("total_entries", 0),
                "failure_count": len(context.get("failures", [])),
            },
        )

    return report


async def handle_log_analysis_command(
    *,
    message: InboundMessage,
    db: DatabaseConnection,
    llm_client: LLMClient | None,
    audit: AuditRepository | None = None,
    look_back_days: int = 7,
    timeout_seconds: float = 60.0,
) -> OutboundMessage:
    """Handle the !analyze-logs chat command."""
    from system_sentinel.chat.base import OutboundMessage
    from system_sentinel.core.exceptions import LLMUnavailableError

    if llm_client is None:
        return OutboundMessage(
            text=(
                "LLM assistant is not configured. "
                "Configure `llm` and `llm_providers` in config.yaml."
            ),
            reply_to=message,
        )

    try:
        report = await perform_log_analysis(
            db=db,
            llm_client=llm_client,
            audit=audit,
            look_back_days=look_back_days,
            source=f"chat:{message.adapter}:{message.user_id}",
            timeout_seconds=timeout_seconds,
        )
    except LLMUnavailableError as exc:
        return OutboundMessage(
            text=f"LLM assistant unavailable: {exc}",
            reply_to=message,
        )

    return OutboundMessage(
        text=f"📋 **Log Analysis (last {look_back_days}d)**\n\n{report[:_MAX_REPORT_CHARS]}",
        reply_to=message,
    )
