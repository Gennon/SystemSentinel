from __future__ import annotations

from pathlib import Path

import aiosqlite


class DatabaseConnection:
    """SQLite connection wrapper that runs schema migrations on connect."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._run_migrations()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    async def _run_migrations(self) -> None:
        assert self._conn is not None

        await self._conn.execute(
            "CREATE TABLE IF NOT EXISTS _migrations "
            "(name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        await self._conn.commit()

        migrations_dir = Path(__file__).parent / "migrations"
        for migration_file in sorted(migrations_dir.glob("*.sql")):
            name = migration_file.name
            cursor = await self._conn.execute(
                "SELECT name FROM _migrations WHERE name = ?", (name,)
            )
            if await cursor.fetchone() is not None:
                continue

            await self._conn.executescript(migration_file.read_text())
            await self._conn.execute(
                "INSERT INTO _migrations (name, applied_at) VALUES (?, datetime('now'))",
                (name,),
            )
            await self._conn.commit()
