from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import json
import shutil
from typing import Any, Protocol, runtime_checkable

from system_sentinel.chat.base import InboundMessage, OutboundMessage
from system_sentinel.tools.firewall.backends import (
    FirewallBackendError,
    UnsupportedFirewallBackendError,
)

_HELP_TEXT = (
    "Available commands:\n"
    "!status - CPU, RAM, disk, uptime, and service health\n"
    "!ask <question> - ask the configured LLM provider for diagnostics help\n"
    "!update - run security updates (confirmation required)\n"
    "!cleanup - run file cleanup (confirmation required)\n"
    "!files - list old files from latest scan\n"
    "!alerts - list active alert conditions\n"
    "!storage - generate storage usage report\n"
    "!snapshots - list recent snapshot/rollback points\n"
    "!anomalies - list recent login anomalies\n"
    "!firewall - show effective firewall rules and desired-state drift status\n"
    "!hardening - show hardening audit results\n"
    "!audit [--count N] - list recent audit log entries\n"
    "!graph <metric> <period> - graph historical metrics (24h, 7d, 30d, 90d)\n"
    "!connections classify - list latest connection intent classifications\n"
    "!help - show this help"
)


@runtime_checkable
class FirewallStatusReporter(Protocol):
    async def status_report(self) -> str: ...


async def handle_files_command(
    *,
    config: dict[str, Any],
    old_files_repo: Any,
    message: InboundMessage,
) -> OutboundMessage:
    monitored = config.get("monitors", {}).get("old_files", {}).get("watched_directories", [])
    if not isinstance(monitored, list) or not monitored:
        return OutboundMessage(text="No watched directories configured.", reply_to=message)

    lines: list[str] = []
    for raw_dir in monitored:
        watched_dir = str(raw_dir).strip()
        if not watched_dir:
            continue
        rows = await old_files_repo.files_for_latest_scan(watched_dir)
        lines.append(f"{watched_dir}: {len(rows)} old file(s)")
        for row in rows[:5]:
            lines.append(f"- {row['file_path']} ({row['age_days']}d, {row['size_bytes']} bytes)")
    if not lines:
        return OutboundMessage(text="No old files found in latest scans.", reply_to=message)
    return OutboundMessage(text="\n".join(lines), reply_to=message)


async def handle_storage_command(
    *,
    config: dict[str, Any],
    message: InboundMessage,
    build_storage_report_sync: Any,
) -> OutboundMessage:
    configured_paths = config.get("tools", {}).get("storage", {}).get("paths")
    paths = configured_paths if isinstance(configured_paths, list) else []
    if not paths:
        old_files_dirs = (
            config.get("monitors", {}).get("old_files", {}).get("watched_directories", [])
        )
        if isinstance(old_files_dirs, list):
            paths = [str(path) for path in old_files_dirs]
    if not paths:
        paths = ["/"]

    disk_threshold = float(
        config.get("monitors", {}).get("disk", {}).get("alert_threshold_percent", 85)
    )
    report = await asyncio.to_thread(build_storage_report_sync, paths, disk_threshold)
    return OutboundMessage(text=report, reply_to=message)


async def handle_anomalies_command(
    *,
    login_repo: Any,
    message: InboundMessage,
) -> OutboundMessage:
    since = datetime.now(UTC) - timedelta(hours=24)
    anomalies = await login_repo.anomalies_since(since, limit=10)
    if not anomalies:
        return OutboundMessage(text="No login anomalies in the last 24 hours.", reply_to=message)

    lines = ["Recent login anomalies:"]
    for row in anomalies:
        anomaly_type = str(row["anomaly_type"]).replace("_", " ")
        username = str(row["username"])
        ip_address = str(row["ip_address"])
        observed_at = str(row["observed_at"])
        details = row["details"] if isinstance(row["details"], dict) else {}
        summary = f"- {observed_at} | {anomaly_type} | user={username} | ip={ip_address}"
        if row["anomaly_type"] == "brute_force":
            attempts = details.get("attempt_count")
            if attempts is not None:
                summary = f"{summary} | attempts={attempts}"
        if row["anomaly_type"] == "impossible_travel":
            distance = details.get("distance_km")
            if distance is not None:
                summary = f"{summary} | distance_km={distance}"
        lines.append(summary)
    return OutboundMessage(text="\n".join(lines), reply_to=message)


async def handle_snapshots_command(*, db: Any, message: InboundMessage) -> OutboundMessage:
    cursor = await db.connection.execute(
        """
        SELECT timestamp, details_json
        FROM audit_log
        WHERE action_type = 'snapshot_create'
          AND outcome = 'success'
        ORDER BY id DESC
        LIMIT 10
        """
    )
    rows = await cursor.fetchall()
    if not rows:
        return OutboundMessage(text="No snapshots recorded yet.", reply_to=message)

    lines = ["Recent snapshots:"]
    for row in rows:
        timestamp = str(row[0])
        details_raw = row[1]
        label = "snapshot"
        backend = "unknown"
        snapshot_id = "n/a"
        if isinstance(details_raw, str):
            try:
                details = json.loads(details_raw)
            except json.JSONDecodeError:
                details = {}
            if isinstance(details, dict):
                label = str(details.get("label", label))
                backend = str(details.get("backend", backend))
                snapshot_id = str(details.get("snapshot_id", snapshot_id))
        lines.append(f"- {timestamp} | {backend} | {snapshot_id} | {label}")
    return OutboundMessage(text="\n".join(lines), reply_to=message)


async def handle_firewall_command(
    *,
    tools: dict[str, Any],
    logger: Any,
    message: InboundMessage,
) -> OutboundMessage:
    firewall_tool = tools.get("firewall")
    if isinstance(firewall_tool, FirewallStatusReporter):
        try:
            report = await firewall_tool.status_report()
        except UnsupportedFirewallBackendError as exc:
            return OutboundMessage(
                text=f"Firewall status unavailable: {exc}",
                reply_to=message,
            )
        except FirewallBackendError as exc:
            return OutboundMessage(
                text=f"Firewall backend error while reading status: {exc}",
                reply_to=message,
            )
        except Exception as exc:
            logger.exception(
                "Unexpected failure in !firewall status_report",
                exc_info=exc,
            )
            return OutboundMessage(
                text="Firewall status failed unexpectedly. Check daemon logs for details.",
                reply_to=message,
            )
        return OutboundMessage(text=report[:3000], reply_to=message)

    ufw_path = shutil.which("ufw")
    if ufw_path:
        proc = await asyncio.create_subprocess_exec(
            ufw_path,
            "status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await proc.communicate()
        text = stdout.decode(errors="replace").strip() or "No firewall status output."
        return OutboundMessage(text=text[:3000], reply_to=message)

    nft_path = shutil.which("nft")
    if nft_path:
        proc = await asyncio.create_subprocess_exec(
            nft_path,
            "list",
            "ruleset",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await proc.communicate()
        text = stdout.decode(errors="replace").strip() or "No firewall rules output."
        return OutboundMessage(text=text[:3000], reply_to=message)

    return OutboundMessage(text="No supported firewall backend detected.", reply_to=message)


async def handle_hardening_command(*, db: Any, message: InboundMessage) -> OutboundMessage:
    cursor = await db.connection.execute(
        """
        SELECT timestamp, description, outcome, details_json
        FROM audit_log
        WHERE action_type = 'tool_run'
          AND (
            details_json LIKE '%"tool": "hardening"%'
            OR description LIKE 'Hardening audit%'
          )
        ORDER BY id DESC
        LIMIT 1
        """
    )
    row = await cursor.fetchone()
    if row is None:
        return OutboundMessage(text="No hardening audit results recorded.", reply_to=message)

    timestamp = str(row[0])
    outcome = str(row[2]).upper()
    details_raw = row[3]
    checks: list[dict[str, Any]] = []
    if isinstance(details_raw, str):
        try:
            parsed = json.loads(details_raw)
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict) and isinstance(parsed.get("checks"), list):
            checks = [item for item in parsed["checks"] if isinstance(item, dict)]

    lines = [f"Latest hardening audit: {timestamp} | {outcome}"]
    if checks:
        for check in checks:
            check_id = str(check.get("id", "unknown"))
            title = str(check.get("title", check_id))
            status = "PASS" if str(check.get("status", "")).lower() == "pass" else "FAIL"
            remediated = bool(check.get("remediated", False))
            suffix = " (auto-remediated)" if remediated else ""
            lines.append(f"- {status} | {title} ({check_id}){suffix}")
    else:
        lines.append(f"- {row[1]}")
    return OutboundMessage(text="\n".join(lines), reply_to=message)


async def handle_audit_command(*, db: Any, message: InboundMessage) -> OutboundMessage:
    parts = message.text.strip().split()
    count = 20
    if len(parts) == 3 and parts[1] == "--count":
        try:
            count = int(parts[2])
        except ValueError:
            return OutboundMessage(text="Usage: !audit [--count N]", reply_to=message)
        if count <= 0:
            return OutboundMessage(text="Usage: !audit [--count N]", reply_to=message)
    elif len(parts) > 1:
        return OutboundMessage(text="Usage: !audit [--count N]", reply_to=message)

    cursor = await db.connection.execute(
        """
        SELECT timestamp, action_type, outcome, source, description
        FROM audit_log
        ORDER BY id DESC
        LIMIT ?
        """,
        (count,),
    )
    rows = await cursor.fetchall()
    if not rows:
        return OutboundMessage(text="No audit entries recorded yet.", reply_to=message)

    lines = [f"Recent audit entries (last {len(rows)}):"]
    for row in rows:
        lines.append(f"- {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]}")
    return OutboundMessage(text="\n".join(lines), reply_to=message)


def handle_help_command(*, message: InboundMessage) -> OutboundMessage:
    return OutboundMessage(text=_HELP_TEXT, reply_to=message)


async def handle_connections_command(
    *,
    connection_repo: Any,
    message: InboundMessage,
) -> OutboundMessage:
    parts = message.text.strip().split()
    subcommand = parts[1].lower() if len(parts) > 1 else ""
    if subcommand != "classify":
        return OutboundMessage(
            text="Usage: !connections classify",
            reply_to=message,
        )

    rows = await connection_repo.latest_classifications(limit=10)
    if not rows:
        return OutboundMessage(
            text="No classified connection sources recorded yet.",
            reply_to=message,
        )

    lines = ["Latest classified connection sources:"]
    for row in rows:
        confidence = float(row["confidence"])
        reasons = row["reasons"] if isinstance(row["reasons"], list) else []
        reasons_str = ", ".join(str(reason) for reason in reasons[:3]) or "no-reason-data"
        lines.append(
            f"- {row['ip_address']} | {row['category']} | confidence={confidence:.2f} | "
            f"action={row['recommended_action']} | reasons={reasons_str}"
        )
    return OutboundMessage(text="\n".join(lines), reply_to=message)
