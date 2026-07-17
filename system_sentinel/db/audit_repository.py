from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


class SqliteAuditRepository:
    """Append-only audit log backed by SQLite.

    Satisfies the ``AuditRepository`` protocol defined in
    ``system_sentinel.core.context``.
    """

    def __init__(
        self,
        db: DatabaseConnection,
        *,
        text_log_path: str | Path | None = None,
        text_log_retention: str | None = None,
    ) -> None:
        self._db = db
        self._text_log_path = Path(text_log_path) if text_log_path is not None else None
        self._text_log_retention = text_log_retention

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
        try:
            if self._text_log_path is not None:
                await asyncio.to_thread(
                    self._append_text_log_line,
                    timestamp=timestamp,
                    action_type=action_type,
                    source=source,
                    description=description,
                    outcome=outcome,
                    details_json=details_json,
                )
        except Exception:
            await self._db.connection.rollback()
            raise
        await self._db.connection.commit()

    async def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most recent *limit* audit entries, newest first."""
        cursor = await self._db.connection.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    def _append_text_log_line(
        self,
        *,
        timestamp: str,
        action_type: str,
        source: str,
        description: str,
        outcome: str,
        details_json: str | None,
    ) -> None:
        if self._text_log_path is None:
            return

        _ = self._text_log_retention
        self._text_log_path.parent.mkdir(parents=True, exist_ok=True)
        line = (
            f"{timestamp} | {action_type} | {outcome} | source={source} | {description}"
            if details_json is None
            else (
                f"{timestamp} | {action_type} | {outcome} | source={source} | {description} | "
                f"details={details_json}"
            )
        )
        with self._text_log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{line}\n")
