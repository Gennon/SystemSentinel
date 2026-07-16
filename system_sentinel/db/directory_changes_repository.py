from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

    from system_sentinel.db.connection import DatabaseConnection


class DirectoryChangesRepository:
    """Stores and queries monitored directory change events (US-018)."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def record_event(
        self,
        *,
        observed_at: datetime,
        watched_directory: str,
        change_type: str,
        file_path: str,
        destination_path: str | None,
        process_owner: str | None,
        alert_suppressed: bool,
        suppression_reason: str | None,
    ) -> None:
        await self._db.connection.execute(
            """
            INSERT INTO directory_change_events (
                observed_at,
                watched_directory,
                change_type,
                file_path,
                destination_path,
                process_owner,
                alert_suppressed,
                suppression_reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observed_at.isoformat(),
                watched_directory,
                change_type,
                file_path,
                destination_path,
                process_owner,
                int(alert_suppressed),
                suppression_reason,
            ),
        )
        await self._db.connection.commit()

    async def recent_events(self, *, limit: int = 20) -> list[dict[str, Any]]:
        cursor = await self._db.connection.execute(
            """
            SELECT
                observed_at,
                watched_directory,
                change_type,
                file_path,
                destination_path,
                process_owner,
                alert_suppressed,
                suppression_reason
            FROM directory_change_events
            ORDER BY observed_at DESC, id DESC
            LIMIT ?
            """,
            (max(1, limit),),
        )
        rows = await cursor.fetchall()
        return [
            {
                "observed_at": str(row[0]),
                "watched_directory": str(row[1]),
                "change_type": str(row[2]),
                "file_path": str(row[3]),
                "destination_path": str(row[4]) if row[4] is not None else None,
                "process_owner": str(row[5]) if row[5] is not None else None,
                "alert_suppressed": bool(row[6]),
                "suppression_reason": str(row[7]) if row[7] is not None else None,
            }
            for row in rows
        ]
