from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


class ConnectionRepository:
    """Stores and queries inbound connections for unknown-IP alerting (US-004)."""

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db

    async def get_last_alerted(
        self, ip_address: str, dest_port: int, protocol: str = "tcp"
    ) -> datetime | None:
        """Return the last_alerted timestamp for this (ip, port, protocol), or None if unseen."""
        cursor = await self._db.connection.execute(
            "SELECT last_alerted FROM known_connections "
            "WHERE ip_address = ? AND dest_port = ? AND protocol = ?",
            (ip_address, dest_port, protocol),
        )
        row = await cursor.fetchone()
        if row and row[0]:
            return datetime.fromisoformat(row[0])
        return None

    async def get_last_alerted_for_ip(
        self, ip_address: str, protocol: str = "tcp"
    ) -> datetime | None:
        """Return latest last_alerted timestamp for this (ip, protocol), across all ports."""
        cursor = await self._db.connection.execute(
            "SELECT last_alerted FROM known_connections "
            "WHERE ip_address = ? AND protocol = ? "
            "ORDER BY last_alerted DESC LIMIT 1",
            (ip_address, protocol),
        )
        row = await cursor.fetchone()
        if row and row[0]:
            return datetime.fromisoformat(row[0])
        return None

    async def upsert(
        self,
        ip_address: str,
        dest_port: int,
        protocol: str,
        now: datetime,
    ) -> None:
        """Insert a new connection record or update last_alerted on repeat."""
        now_iso = now.isoformat()
        await self._db.connection.execute(
            """
            INSERT INTO known_connections (ip_address, dest_port, protocol, first_seen, last_alerted)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (ip_address, dest_port, protocol)
            DO UPDATE SET last_alerted = excluded.last_alerted
            """,
            (ip_address, dest_port, protocol, now_iso, now_iso),
        )
        await self._db.connection.commit()
