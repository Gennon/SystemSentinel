from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


class LoginRepository:
    """Stores and queries failed SSH login attempts."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def record(
        self,
        *,
        ip_address: str,
        username: str,
        timestamp: datetime,
        port: int | None = None,
        host: str = "",
    ) -> None:
        """Append a single failed login attempt."""
        await self._db.connection.execute(
            """
            INSERT INTO login_attempts (timestamp, ip_address, username, port, host)
            VALUES (?, ?, ?, ?, ?)
            """,
            (timestamp.isoformat(), ip_address, username, port, host),
        )
        await self._db.connection.commit()

    async def count_since(self, ip_address: str, since: datetime) -> int:
        """Return the number of failed attempts from *ip_address* on or after *since*."""
        cursor = await self._db.connection.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND timestamp >= ?",
            (ip_address, since.isoformat()),
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def usernames_since(self, ip_address: str, since: datetime) -> list[str]:
        """Return distinct usernames tried from *ip_address* on or after *since*."""
        cursor = await self._db.connection.execute(
            """
            SELECT DISTINCT username
            FROM login_attempts
            WHERE ip_address = ? AND timestamp >= ?
            ORDER BY username
            """,
            (ip_address, since.isoformat()),
        )
        rows = await cursor.fetchall()
        return [row[0] for row in rows]

    async def unique_ips_since(self, since: datetime) -> list[dict[str, Any]]:
        """Return attacking IPs with attempt counts since *since*, for digest reports."""
        cursor = await self._db.connection.execute(
            """
            SELECT ip_address, COUNT(*) AS attempts
            FROM login_attempts
            WHERE timestamp >= ?
            GROUP BY ip_address
            ORDER BY attempts DESC
            """,
            (since.isoformat(),),
        )
        rows = await cursor.fetchall()
        return [{"ip_address": row[0], "attempts": row[1]} for row in rows]

    async def latest_timestamp(self) -> datetime | None:
        """Return the timestamp of the most recently stored attempt, or None."""
        cursor = await self._db.connection.execute("SELECT MAX(timestamp) FROM login_attempts")
        row = await cursor.fetchone()
        if row and row[0]:
            return datetime.fromisoformat(row[0])
        return None
