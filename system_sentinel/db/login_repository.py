from __future__ import annotations

from datetime import datetime
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.db.connection import DatabaseConnection


class LoginRepository:
    """Stores login attempts and anomaly records."""

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
        auth_method: str = "unknown",
    ) -> None:
        """Append a single failed login attempt (US-003 compatibility API)."""
        await self.record_failed_login(
            ip_address=ip_address,
            username=username,
            timestamp=timestamp,
            port=port,
            host=host,
            auth_method=auth_method,
        )

    async def record_failed_login(
        self,
        *,
        ip_address: str,
        username: str,
        timestamp: datetime,
        port: int | None = None,
        host: str = "",
        auth_method: str = "unknown",
    ) -> None:
        """Append a single failed login attempt."""
        _ = auth_method
        await self._db.connection.execute(
            """
            INSERT INTO login_attempts (timestamp, ip_address, username, port, host)
            VALUES (?, ?, ?, ?, ?)
            """,
            (timestamp.isoformat(), ip_address, username, port, host),
        )
        await self._db.connection.commit()

    async def record_successful_login(
        self,
        *,
        ip_address: str,
        username: str,
        timestamp: datetime,
        port: int | None = None,
        host: str = "",
        auth_method: str = "unknown",
    ) -> None:
        """Append a single successful login."""
        await self._db.connection.execute(
            """
            INSERT INTO login_successes (timestamp, ip_address, username, port, auth_method, host)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (timestamp.isoformat(), ip_address, username, port, auth_method, host),
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

    async def has_successful_login(self, username: str, *, before: datetime | None = None) -> bool:
        """Return True when *username* has at least one successful login."""
        if before is None:
            cursor = await self._db.connection.execute(
                "SELECT 1 FROM login_successes WHERE username = ? LIMIT 1",
                (username,),
            )
        else:
            cursor = await self._db.connection.execute(
                """
                SELECT 1
                FROM login_successes
                WHERE username = ? AND timestamp < ?
                LIMIT 1
                """,
                (username, before.isoformat()),
            )
        row = await cursor.fetchone()
        return row is not None

    async def latest_successful_login_for_user(
        self,
        username: str,
        *,
        before: datetime | None = None,
        since: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Return latest successful login for *username* under the supplied window."""
        clauses = ["username = ?"]
        params: list[object] = [username]
        if before is not None:
            clauses.append("timestamp < ?")
            params.append(before.isoformat())
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        where = " AND ".join(clauses)
        cursor = await self._db.connection.execute(
            f"""
            SELECT timestamp, ip_address, username, port, auth_method, host
            FROM login_successes
            WHERE {where}
            ORDER BY timestamp DESC, id DESC
            LIMIT 1
            """,
            tuple(params),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "timestamp": str(row[0]),
            "ip_address": str(row[1]),
            "username": str(row[2]),
            "port": int(row[3]) if row[3] is not None else None,
            "auth_method": str(row[4]),
            "host": str(row[5]),
        }

    async def record_anomaly(
        self,
        *,
        observed_at: datetime,
        anomaly_type: str,
        username: str,
        ip_address: str,
        details: dict[str, Any],
    ) -> None:
        """Persist one login anomaly record."""
        await self._db.connection.execute(
            """
            INSERT INTO login_anomalies (observed_at, anomaly_type, username, ip_address, details_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                observed_at.isoformat(),
                anomaly_type,
                username,
                ip_address,
                json.dumps(details),
            ),
        )
        await self._db.connection.commit()

    async def anomalies_since(self, since: datetime, *, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent anomaly records on/after *since*."""
        cursor = await self._db.connection.execute(
            """
            SELECT observed_at, anomaly_type, username, ip_address, details_json
            FROM login_anomalies
            WHERE observed_at >= ?
            ORDER BY observed_at DESC, id DESC
            LIMIT ?
            """,
            (since.isoformat(), max(1, limit)),
        )
        rows = await cursor.fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            details_raw = row[4]
            details: dict[str, Any] = {}
            if isinstance(details_raw, str):
                try:
                    parsed = json.loads(details_raw)
                except json.JSONDecodeError:
                    parsed = {}
                if isinstance(parsed, dict):
                    details = parsed
            results.append(
                {
                    "observed_at": str(row[0]),
                    "anomaly_type": str(row[1]),
                    "username": str(row[2]),
                    "ip_address": str(row[3]),
                    "details": details,
                }
            )
        return results
