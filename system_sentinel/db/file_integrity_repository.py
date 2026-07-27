from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

    from system_sentinel.db.connection import DatabaseConnection


class FileIntegrityRepository:
    """Persists file-integrity baselines and verification history (US-030)."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def get_baseline(self, path: str) -> dict[str, Any] | None:
        cursor = await self._db.connection.execute(
            """
            SELECT
                path,
                source_path,
                expected_sha256,
                created_at,
                updated_at,
                last_verified_at,
                last_status,
                last_actual_sha256,
                last_error
            FROM file_integrity_baselines
            WHERE path = ?
            """,
            (path,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def upsert_baseline(
        self,
        *,
        path: str,
        source_path: str,
        expected_sha256: str,
        observed_at: datetime,
    ) -> None:
        timestamp = observed_at.isoformat()
        await self._db.connection.execute(
            """
            INSERT INTO file_integrity_baselines (
                path,
                source_path,
                expected_sha256,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (path) DO UPDATE SET
                source_path = excluded.source_path,
                expected_sha256 = excluded.expected_sha256,
                updated_at = excluded.updated_at
            """,
            (path, source_path, expected_sha256, timestamp, timestamp),
        )
        await self._db.connection.commit()

    async def record_verification(
        self,
        *,
        path: str,
        checked_at: datetime,
        expected_sha256: str | None,
        actual_sha256: str | None,
        status: str,
        error: str | None = None,
    ) -> None:
        checked_at_iso = checked_at.isoformat()
        await self._db.connection.execute(
            """
            INSERT INTO file_integrity_events (
                checked_at,
                path,
                expected_sha256,
                actual_sha256,
                status,
                error
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (checked_at_iso, path, expected_sha256, actual_sha256, status, error),
        )
        await self._db.connection.execute(
            """
            UPDATE file_integrity_baselines
            SET
                last_verified_at = ?,
                last_status = ?,
                last_actual_sha256 = ?,
                last_error = ?
            WHERE path = ?
            """,
            (checked_at_iso, status, actual_sha256, error, path),
        )
        await self._db.connection.commit()

    async def list_statuses(self, paths: list[str]) -> list[dict[str, Any]]:
        if not paths:
            return []
        placeholders = ", ".join("?" for _ in paths)
        cursor = await self._db.connection.execute(
            f"""
            SELECT
                path,
                source_path,
                expected_sha256,
                created_at,
                updated_at,
                last_verified_at,
                last_status,
                last_actual_sha256,
                last_error
            FROM file_integrity_baselines
            WHERE path IN ({placeholders})
            ORDER BY path ASC
            """,
            tuple(paths),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_state(self, key: str) -> str | None:
        cursor = await self._db.connection.execute(
            "SELECT value FROM monitor_state WHERE key = ?",
            (key,),
        )
        row = await cursor.fetchone()
        return str(row[0]) if row is not None else None

    async def set_state(self, key: str, value: str) -> None:
        await self._db.connection.execute(
            """
            INSERT INTO monitor_state (key, value)
            VALUES (?, ?)
            ON CONFLICT (key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        await self._db.connection.commit()
