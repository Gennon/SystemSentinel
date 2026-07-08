from __future__ import annotations

from datetime import UTC, datetime
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


class MetricsRepository:
    """Stores and retrieves system metrics (US-005)."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def insert(
        self,
        metric_type: str,
        data: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> None:
        """Persist a single metric sample."""
        ts = (timestamp or datetime.now(UTC)).isoformat()
        await self._db.connection.execute(
            "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
            (ts, metric_type, json.dumps(data)),
        )
        await self._db.connection.commit()

    async def query_range(
        self,
        metric_type: str,
        since: datetime,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return all samples of *metric_type* in the given time range."""
        until = until or datetime.now(UTC)
        cursor = await self._db.connection.execute(
            "SELECT timestamp, data_json FROM system_metrics "
            "WHERE metric_type = ? AND timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp ASC",
            (metric_type, since.isoformat(), until.isoformat()),
        )
        rows = await cursor.fetchall()
        return [{"timestamp": row[0], **json.loads(row[1])} for row in rows]

    async def purge_old(self, metric_type: str | None, cutoff: datetime) -> int:
        """Delete records older than *cutoff*.  Pass ``None`` to purge all types.

        Returns the number of rows deleted.
        """
        if metric_type is None:
            cursor = await self._db.connection.execute(
                "DELETE FROM system_metrics WHERE timestamp < ?",
                (cutoff.isoformat(),),
            )
        else:
            cursor = await self._db.connection.execute(
                "DELETE FROM system_metrics WHERE metric_type = ? AND timestamp < ?",
                (metric_type, cutoff.isoformat()),
            )
        await self._db.connection.commit()
        return cursor.rowcount
