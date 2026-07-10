from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

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

    async def record_attempt(
        self,
        ip_address: str,
        dest_port: int,
        protocol: str,
        timestamp: datetime,
    ) -> None:
        """Append one observed unknown inbound connection attempt."""
        await self._db.connection.execute(
            """
            INSERT INTO connection_attempts (timestamp, ip_address, dest_port, protocol)
            VALUES (?, ?, ?, ?)
            """,
            (timestamp.isoformat(), ip_address, dest_port, protocol),
        )
        await self._db.connection.commit()

    async def count_attempts_since(self, ip_address: str, since: datetime) -> int:
        """Return attempt count for *ip_address* on or after *since*."""
        cursor = await self._db.connection.execute(
            "SELECT COUNT(*) FROM connection_attempts WHERE ip_address = ? AND timestamp >= ?",
            (ip_address, since.isoformat()),
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def ports_since(self, ip_address: str, since: datetime) -> list[int]:
        """Return distinct destination ports touched by *ip_address* since *since*."""
        cursor = await self._db.connection.execute(
            """
            SELECT DISTINCT dest_port
            FROM connection_attempts
            WHERE ip_address = ? AND timestamp >= ?
            ORDER BY dest_port
            """,
            (ip_address, since.isoformat()),
        )
        rows = await cursor.fetchall()
        return [int(row[0]) for row in rows]

    async def ip_port_activity_since(self, since: datetime) -> list[dict[str, Any]]:
        """Return grouped attempt counts by IP and destination port since *since*."""
        cursor = await self._db.connection.execute(
            """
            SELECT ip_address, dest_port, COUNT(*) AS attempts
            FROM connection_attempts
            WHERE timestamp >= ?
            GROUP BY ip_address, dest_port
            ORDER BY attempts DESC, ip_address, dest_port
            """,
            (since.isoformat(),),
        )
        rows = await cursor.fetchall()
        return [
            {"ip_address": row[0], "dest_port": int(row[1]), "attempts": int(row[2])}
            for row in rows
        ]

    async def get_state(self, key: str) -> str | None:
        """Return a monitor state value by *key* or ``None`` when missing."""
        cursor = await self._db.connection.execute(
            "SELECT value FROM monitor_state WHERE key = ?",
            (key,),
        )
        row = await cursor.fetchone()
        return str(row[0]) if row else None

    async def set_state(self, key: str, value: str) -> None:
        """Persist or update a monitor state value."""
        await self._db.connection.execute(
            """
            INSERT INTO monitor_state (key, value)
            VALUES (?, ?)
            ON CONFLICT (key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        await self._db.connection.commit()

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
