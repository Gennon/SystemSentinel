from __future__ import annotations

from datetime import UTC, datetime
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


class SqliteAuditRepository:
    """Append-only audit log backed by SQLite.

    Satisfies the ``AuditRepository`` protocol defined in
    ``system_sentinel.core.context``.
    """

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def append(
        self,
        action_type: str,
        source: str,
        description: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        timestamp = datetime.now(UTC).isoformat()
        details_json = json.dumps(details) if details is not None else None

        await self._db.connection.execute(
            """
            INSERT INTO audit_log
                (timestamp, action_type, source, description, outcome, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp, action_type, source, description, outcome, details_json),
        )
        await self._db.connection.commit()

    async def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most recent *limit* audit entries, newest first."""
        cursor = await self._db.connection.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
