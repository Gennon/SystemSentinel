from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

    from system_sentinel.db.connection import DatabaseConnection


class OldFilesRepository:
    """Stores and queries old-file scan results (US-007)."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def record_scan(
        self,
        watched_directory: str,
        age_threshold_days: int,
        scanned_at: datetime,
        files: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Persist one scan for a watched directory and return its summary row."""
        file_count = len(files)
        total_size_bytes = sum(int(f["size_bytes"]) for f in files)
        cursor = await self._db.connection.execute(
            """
            INSERT INTO old_file_scans (
                scanned_at, watched_directory, age_threshold_days, file_count, total_size_bytes
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scanned_at.isoformat(),
                watched_directory,
                age_threshold_days,
                file_count,
                total_size_bytes,
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("Failed to obtain scan row id after insert")
        scan_id = int(cursor.lastrowid)
        if files:
            await self._db.connection.executemany(
                """
                INSERT INTO old_file_entries (scan_id, file_path, size_bytes, last_modified, age_days)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        str(f["file_path"]),
                        int(f["size_bytes"]),
                        str(f["last_modified"]),
                        int(f["age_days"]),
                    )
                    for f in files
                ],
            )
        await self._db.connection.commit()

        return {
            "scan_id": scan_id,
            "scanned_at": scanned_at.isoformat(),
            "watched_directory": watched_directory,
            "age_threshold_days": age_threshold_days,
            "file_count": file_count,
            "total_size_bytes": total_size_bytes,
        }

    async def files_for_latest_scan(self, watched_directory: str) -> list[dict[str, Any]]:
        """Return files from the latest scan for *watched_directory*."""
        cursor = await self._db.connection.execute(
            """
            SELECT e.file_path, e.size_bytes, e.last_modified, e.age_days
            FROM old_file_entries e
            JOIN old_file_scans s ON s.id = e.scan_id
            WHERE s.id = (
                SELECT id
                FROM old_file_scans
                WHERE watched_directory = ?
                ORDER BY scanned_at DESC, id DESC
                LIMIT 1
            )
            ORDER BY e.age_days DESC, e.file_path ASC
            """,
            (watched_directory,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "file_path": str(row[0]),
                "size_bytes": int(row[1]),
                "last_modified": str(row[2]),
                "age_days": int(row[3]),
            }
            for row in rows
        ]

    async def latest_scan_summaries(self, since: datetime) -> list[dict[str, Any]]:
        """Return most recent per-directory scan summaries on/after *since*."""
        cursor = await self._db.connection.execute(
            """
            SELECT id, scanned_at, watched_directory, age_threshold_days, file_count, total_size_bytes
            FROM old_file_scans
            WHERE scanned_at >= ?
            ORDER BY watched_directory ASC, scanned_at DESC, id DESC
            """,
            (since.isoformat(),),
        )
        rows = await cursor.fetchall()
        seen_directories: set[str] = set()
        summaries: list[dict[str, Any]] = []
        for row in rows:
            watched_directory = str(row[2])
            if watched_directory in seen_directories:
                continue
            seen_directories.add(watched_directory)
            summaries.append(
                {
                    "scan_id": int(row[0]),
                    "scanned_at": str(row[1]),
                    "watched_directory": watched_directory,
                    "age_threshold_days": int(row[3]),
                    "file_count": int(row[4]),
                    "total_size_bytes": int(row[5]),
                }
            )
        return summaries

    async def get_state(self, key: str) -> str | None:
        cursor = await self._db.connection.execute(
            "SELECT value FROM monitor_state WHERE key = ?",
            (key,),
        )
        row = await cursor.fetchone()
        return str(row[0]) if row else None

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
