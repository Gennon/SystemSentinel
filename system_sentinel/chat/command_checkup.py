"""Full system check command (US-045).

Gathers data from all sentinel sources via the existing repository layer,
sends results to the LLM for synthesis, and returns a prioritized report
with severity levels.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from typing import TYPE_CHECKING, Any

import psutil

if TYPE_CHECKING:
    from system_sentinel.chat.base import InboundMessage, OutboundMessage
    from system_sentinel.core.context import AuditRepository, LLMClient
    from system_sentinel.db.audit_repository import SqliteAuditRepository
    from system_sentinel.db.connection import DatabaseConnection
    from system_sentinel.db.file_integrity_repository import FileIntegrityRepository
    from system_sentinel.db.login_repository import LoginRepository
    from system_sentinel.db.vulnerability_repository import VulnerabilityRepository

_CHECKUP_SYSTEM_PROMPT = (
    "You are SystemSentinel, a Linux system management assistant. "
    "You have been given a comprehensive snapshot of the current system state. "
    "Produce a prioritized health report with concrete improvement suggestions. "
    "Format your response as a numbered list of findings, each on its own line, "
    "starting with a severity tag: [CRITICAL], [WARNING], or [INFO]. "
    "Be concise and actionable. If everything looks healthy, say so clearly."
)

_MAX_REPORT_CHARS = 3000


async def gather_checkup_context(
    *,
    vuln_repo: VulnerabilityRepository,
    login_repo: LoginRepository,
    integrity_repo: FileIntegrityRepository,
    audit_repo: SqliteAuditRepository,
) -> dict[str, Any]:
    """Collect the latest data from all sentinel data sources via repositories."""
    ctx: dict[str, Any] = {}

    # Current resource usage
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    ctx["resources"] = {
        "cpu_percent": cpu,
        "ram_percent": ram.percent,
        "disk_percent": disk.percent,
    }

    # Latest vulnerability scan — VulnerabilityRepository.latest_scan()
    scan = await vuln_repo.latest_scan()
    if scan is not None:
        ctx["vulnscan"] = {
            "scanned_at": scan["scanned_at"],
            "score": scan.get("score"),
            "warning_count": int(scan.get("warning_count", 0)),
            "suggestion_count": int(scan.get("suggestion_count", 0)),
            "top_findings": scan.get("top_findings", [])[:5],
        }

    # Latest hardening audit — SqliteAuditRepository.latest_hardening_audit()
    hardening_row = await audit_repo.latest_hardening_audit()
    if hardening_row is not None:
        details_raw = hardening_row.get("details_json")
        checks: list[dict[str, Any]] = []
        if isinstance(details_raw, str):
            try:
                parsed_details = json.loads(details_raw)
                if isinstance(parsed_details, dict) and isinstance(
                    parsed_details.get("checks"), list
                ):
                    checks = [item for item in parsed_details["checks"] if isinstance(item, dict)]
            except json.JSONDecodeError:
                pass
        failed_checks = [c for c in checks if str(c.get("status", "")).lower() != "pass"]
        ctx["hardening"] = {
            "timestamp": hardening_row["timestamp"],
            "outcome": hardening_row["outcome"],
            "total_checks": len(checks),
            "failed_checks": [
                {
                    "id": c.get("id", "?"),
                    "title": c.get("title", "?"),
                    "remediated": c.get("remediated", False),
                }
                for c in failed_checks[:5]
            ],
        }

    # Recent login anomalies (last 7 days) — LoginRepository.anomalies_since()
    since_7d = datetime.now(UTC) - timedelta(days=7)
    anomaly_rows = await login_repo.anomalies_since(since_7d, limit=10)
    ctx["login_anomalies"] = [
        {
            "type": str(row["anomaly_type"]),
            "username": str(row["username"]),
            "ip": str(row["ip_address"]),
            "observed_at": str(row["observed_at"]),
        }
        for row in anomaly_rows
    ]

    # Recent alerts from audit log (last 24h) — SqliteAuditRepository.recent_by_type()
    since_24h = datetime.now(UTC) - timedelta(hours=24)
    alert_rows = await audit_repo.recent_by_type("alert_fired", 10, since=since_24h)
    recent_alerts: list[dict[str, str]] = []
    for row in alert_rows:
        severity = "unknown"
        raw_dj = row.get("details_json")
        if isinstance(raw_dj, str):
            try:
                dj = json.loads(raw_dj)
                if isinstance(dj, dict):
                    s = dj.get("severity")
                    if isinstance(s, str) and s.strip():
                        severity = s.strip()
            except json.JSONDecodeError:
                pass
        recent_alerts.append(
            {
                "timestamp": str(row["timestamp"]),
                "description": str(row["description"]),
                "severity": severity,
            }
        )
    ctx["recent_alerts"] = recent_alerts

    # Service health events — SqliteAuditRepository.recent_by_type()
    service_rows = await audit_repo.recent_by_type("service_health", 5)
    ctx["service_health"] = [
        {
            "timestamp": str(row["timestamp"]),
            "description": str(row["description"]),
            "outcome": str(row["outcome"]),
        }
        for row in service_rows
    ]

    # File integrity mismatches — FileIntegrityRepository.recent_mismatches()
    ctx["integrity_mismatches"] = await integrity_repo.recent_mismatches(limit=5)

    return ctx


def build_checkup_prompt(context: dict[str, Any]) -> str:
    """Build the LLM prompt from gathered context data."""
    lines: list[str] = [
        f"Full system check performed at {datetime.now(UTC).isoformat()}",
        "",
        "=== RESOURCE USAGE ===",
    ]

    resources = context.get("resources", {})
    lines.append(f"CPU: {resources.get('cpu_percent', 'n/a')}%")
    lines.append(f"RAM: {resources.get('ram_percent', 'n/a')}%")
    lines.append(f"Disk (/): {resources.get('disk_percent', 'n/a')}%")

    lines.append("")
    lines.append("=== VULNERABILITY SCAN ===")
    vscan = context.get("vulnscan")
    if vscan:
        lines.append(f"Last scan: {vscan['scanned_at']}")
        lines.append(
            f"Score: {vscan['score']}, Warnings: {vscan['warning_count']}, "
            f"Suggestions: {vscan['suggestion_count']}"
        )
        if vscan["top_findings"]:
            lines.append("Top findings: " + "; ".join(str(f) for f in vscan["top_findings"]))
    else:
        lines.append("No vulnerability scan data available.")

    lines.append("")
    lines.append("=== HARDENING AUDIT ===")
    hardening = context.get("hardening")
    if hardening:
        lines.append(f"Last audit: {hardening['timestamp']} | outcome={hardening['outcome']}")
        lines.append(
            f"Total checks: {hardening['total_checks']}, Failed: {len(hardening['failed_checks'])}"
        )
        for fc in hardening["failed_checks"]:
            remediated = " (auto-remediated)" if fc.get("remediated") else ""
            lines.append(f"  FAIL: {fc['title']} ({fc['id']}){remediated}")
    else:
        lines.append("No hardening audit data available.")

    lines.append("")
    lines.append("=== LOGIN ANOMALIES (last 7 days) ===")
    anomalies = context.get("login_anomalies", [])
    if anomalies:
        for a in anomalies:
            lines.append(
                f"  {a['observed_at']} | {a['type']} | user={a['username']} | ip={a['ip']}"
            )
    else:
        lines.append("None detected.")

    lines.append("")
    lines.append("=== RECENT ALERTS (last 24h) ===")
    alerts = context.get("recent_alerts", [])
    if alerts:
        for a in alerts:
            lines.append(f"  {a['timestamp']} | {a['severity']} | {a['description']}")
    else:
        lines.append("None.")

    lines.append("")
    lines.append("=== SERVICE HEALTH ===")
    services = context.get("service_health", [])
    if services:
        for s in services:
            lines.append(f"  {s['timestamp']} | {s['outcome']} | {s['description']}")
    else:
        lines.append("No recent service health data.")

    lines.append("")
    lines.append("=== FILE INTEGRITY ===")
    mismatches = context.get("integrity_mismatches", [])
    if mismatches:
        for m in mismatches:
            lines.append(f"  MISMATCH: {m['file_path']} (checked at {m['checked_at']})")
    else:
        lines.append("No integrity mismatches detected.")

    lines.append("")
    lines.append(
        "Based on all of the above, provide a prioritized health report with concrete "
        "improvement suggestions. Each finding must start with [CRITICAL], [WARNING], or [INFO]."
    )

    return "\n".join(lines)


def _make_repos(
    db: DatabaseConnection,
) -> tuple[
    VulnerabilityRepository,
    LoginRepository,
    FileIntegrityRepository,
    SqliteAuditRepository,
]:
    """Instantiate all repositories needed for a checkup from one DatabaseConnection."""
    from system_sentinel.db.audit_repository import SqliteAuditRepository
    from system_sentinel.db.file_integrity_repository import FileIntegrityRepository
    from system_sentinel.db.login_repository import LoginRepository
    from system_sentinel.db.vulnerability_repository import VulnerabilityRepository

    return (
        VulnerabilityRepository(db),
        LoginRepository(db),
        FileIntegrityRepository(db),
        SqliteAuditRepository(db),
    )


async def perform_checkup(
    *,
    db: DatabaseConnection,
    llm_client: LLMClient,
    audit: AuditRepository | None = None,
    source: str = "chat",
    timeout_seconds: float = 60.0,
) -> str:
    """Run the full system check and return the synthesized LLM report."""
    vuln_repo, login_repo, integrity_repo, audit_repo = _make_repos(db)

    context = await gather_checkup_context(
        vuln_repo=vuln_repo,
        login_repo=login_repo,
        integrity_repo=integrity_repo,
        audit_repo=audit_repo,
    )
    prompt = build_checkup_prompt(context)

    result = await llm_client.complete(
        prompt=prompt,
        system_prompt=_CHECKUP_SYSTEM_PROMPT,
        timeout_seconds=timeout_seconds,
    )

    report: str = str(result.text).strip()

    if audit is not None:
        await audit.append(
            action_type="system_checkup",
            source=source,
            description="AI full system check completed.",
            outcome="success",
            details={
                "provider": result.provider,
                "model": result.model_used,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "resource_snapshot": context.get("resources", {}),
                "anomaly_count": len(context.get("login_anomalies", [])),
                "alert_count": len(context.get("recent_alerts", [])),
                "integrity_mismatches": len(context.get("integrity_mismatches", [])),
            },
        )

    return report


async def handle_checkup_command(
    *,
    message: InboundMessage,
    db: DatabaseConnection,
    llm_client: LLMClient | None,
    audit: AuditRepository | None = None,
    timeout_seconds: float = 60.0,
) -> OutboundMessage:
    """Handle the !checkup chat command."""
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
        report = await perform_checkup(
            db=db,
            llm_client=llm_client,
            audit=audit,
            source=f"chat:{message.adapter}:{message.user_id}",
            timeout_seconds=timeout_seconds,
        )
    except LLMUnavailableError as exc:
        return OutboundMessage(
            text=f"LLM assistant unavailable: {exc}",
            reply_to=message,
        )

    return OutboundMessage(
        text=f"🔍 **Full System Check**\n\n{report[:_MAX_REPORT_CHARS]}",
        reply_to=message,
    )
