from __future__ import annotations

from datetime import UTC, datetime, timedelta
import re
from typing import TYPE_CHECKING, Any

from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.login_repository import LoginRepository


# Matches both:
#   "Failed password for root from 1.2.3.4 port 22 ssh2"
#   "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
#   "Connection closed by invalid user test 1.2.3.4 port 22 [preauth]"
_FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+) port (\d+)"
)
_CONN_CLOSED_RE = re.compile(
    r"Connection closed by (?:invalid user )?(\S+) ([\d.:a-fA-F]+) port (\d+)"
)


def parse_failed_ssh_line(line: str) -> dict[str, Any] | None:
    """Parse a single auth log line and return extracted fields, or None if not a failure."""
    for pattern in (_FAILED_PASSWORD_RE, _CONN_CLOSED_RE):
        match = pattern.search(line)
        if match:
            username, ip_address, port_str = match.groups()
            return {
                "username": username,
                "ip_address": ip_address,
                "port": int(port_str),
            }
    return None


class LoginMonitor(BaseMonitor):
    """Monitors the system auth log for failed SSH login attempts.

    Stores each failure in the database and fires a brute-force alert event
    when the configured threshold is exceeded within the time window.
    """

    name = "logins"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        login_repo: LoginRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._login_repo = login_repo
        self._alerted_ips: set[str] = set()

    async def _get_login_repo(self) -> LoginRepository:
        if self._login_repo is not None:
            return self._login_repo
        # Deferred import to avoid circular dependency at module level.
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.login_repository import LoginRepository as _Repo

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        repo = _Repo(db)
        self._login_repo = repo
        return repo

    async def collect(self) -> None:
        """Read new auth log entries, store them, and fire alert events as needed."""
        repo = await self._get_login_repo()
        alert_count: int = int(self.config.get("failed_login_alert_count", 5))
        window_minutes: int = int(self.config.get("failed_login_window_minutes", 10))
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=window_minutes)

        lines = await self._read_new_log_lines()
        affected_ips: set[str] = set()

        for line in lines:
            parsed = parse_failed_ssh_line(line)
            if parsed is None:
                continue
            try:
                await repo.record(
                    ip_address=parsed["ip_address"],
                    username=parsed["username"],
                    port=parsed["port"],
                    timestamp=now,
                )
                affected_ips.add(parsed["ip_address"])
            except Exception:
                self.logger.exception(
                    "Failed to record login attempt from %s", parsed["ip_address"]
                )

        for ip in affected_ips:
            if ip in self._alerted_ips:
                continue
            count = await repo.count_since(ip, window_start)
            if count >= alert_count:
                usernames = await repo.usernames_since(ip, window_start)
                await self.ctx.event_bus.publish(
                    "alert.login.brute_force_detected",
                    {
                        "ip_address": ip,
                        "attempt_count": count,
                        "usernames": usernames,
                        "window_minutes": window_minutes,
                    },
                )
                self._alerted_ips.add(ip)
                self.logger.warning(
                    "Brute-force alert: %d failed attempts from %s in %d minutes",
                    count,
                    ip,
                    window_minutes,
                )

    async def _read_new_log_lines(self) -> list[str]:
        """Return new auth log lines since the last collection run.

        Tries journald first; falls back to /var/log/auth.log.
        Wrapped in asyncio.to_thread to avoid blocking the event loop.
        """
        import asyncio

        try:
            return await asyncio.to_thread(self._read_journald)
        except Exception:
            self.logger.debug("journald not available, falling back to auth.log")
        try:
            return await asyncio.to_thread(self._read_auth_log)
        except Exception:
            self.logger.warning("Could not read any SSH auth log source.")
            return []

    def _read_journald(self) -> list[str]:
        import subprocess

        window_minutes: int = int(self.config.get("failed_login_window_minutes", 10))
        result = subprocess.run(
            [
                "/usr/bin/journalctl",
                "--identifier=sshd",
                f"--since={window_minutes} minutes ago",
                "--no-pager",
                "--output=short",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"journalctl exited {result.returncode}: {result.stderr}")
        return result.stdout.splitlines()

    def _read_auth_log(self) -> list[str]:
        with open("/var/log/auth.log") as fh:
            return fh.readlines()
