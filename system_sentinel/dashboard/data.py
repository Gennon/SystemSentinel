from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.command_metrics import get_active_alert_conditions

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    source: str
    action_type: str
    outcome: str
    description: str


@dataclass(frozen=True)
class DashboardSnapshot:
    metrics: dict[str, dict[str, Any]]
    active_alerts: list[str]
    audit_entries: list[AuditEntry]
    generated_at: datetime


async def _load_latest_metrics(db: DatabaseConnection) -> dict[str, dict[str, Any]]:
    cursor = await db.connection.execute(
        """
        SELECT metric_type, timestamp, data_json
        FROM system_metrics
        WHERE id IN (
            SELECT MAX(id) FROM system_metrics GROUP BY metric_type
        )
        """
    )
    rows = await cursor.fetchall()

    metrics: dict[str, dict[str, Any]] = {}
    for row in rows:
        metric_type = str(row[0])
        timestamp = str(row[1])
        data_raw = row[2]
        if not isinstance(data_raw, str):
            continue
        try:
            data = json.loads(data_raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        metrics[metric_type] = {"timestamp": timestamp, **data}
    return metrics


async def _load_recent_audit_entries(db: DatabaseConnection, *, limit: int) -> list[AuditEntry]:
    cursor = await db.connection.execute(
        """
        SELECT timestamp, source, action_type, outcome, description
        FROM audit_log
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, limit),),
    )
    rows = await cursor.fetchall()
    return [
        AuditEntry(
            timestamp=str(row[0]),
            source=str(row[1]),
            action_type=str(row[2]),
            outcome=str(row[3]),
            description=str(row[4]),
        )
        for row in rows
    ]


async def load_dashboard_snapshot(
    *,
    db: DatabaseConnection,
    config: dict[str, Any],
    audit_limit: int = 20,
) -> DashboardSnapshot:
    now = datetime.now(UTC)
    metrics = await _load_latest_metrics(db)
    active_alerts = await get_active_alert_conditions(
        config=config,
        db=db,
        now_iso=now.isoformat(),
    )
    audit_entries = await _load_recent_audit_entries(db, limit=audit_limit)
    return DashboardSnapshot(
        metrics=metrics,
        active_alerts=active_alerts,
        audit_entries=audit_entries,
        generated_at=now,
    )
