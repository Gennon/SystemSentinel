from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
import ipaddress
import re
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.connection_repository import ConnectionRepository


# Matches lines from `ss -tnp` / `ss -tnpa` ESTAB rows.
# Local address:port is group 1+2, peer address:port is group 3+4.
# Handles both IPv4 (1.2.3.4:22) and IPv6 ([::1]:22) formats.
_SS_LINE_RE = re.compile(
    r"^ESTAB\s+"  # connection state
    r"\d+\s+\d+\s+"  # Recv-Q / Send-Q
    # local address:port — IPv6 [addr]:port or IPv4 addr:port
    r"(?:\[(?P<local_ip6>[^\]]+)\]|(?P<local_ip4>[^:\s]+)):(?P<local_port>\d+)\s+"
    # peer address:port
    r"(?:\[(?P<peer_ip6>[^\]]+)\]|(?P<peer_ip4>[^:\s]+)):(?P<peer_port>\d+)",
    re.IGNORECASE,
)


def parse_ss_line(line: str) -> dict[str, Any] | None:
    """Parse a single `ss -tnp` output line.

    Returns a dict with ``src_ip``, ``dest_port``, ``protocol`` keys for
    ESTABLISHED inbound connections, or ``None`` if the line is not relevant.
    """
    match = _SS_LINE_RE.match(line.strip())
    if not match:
        return None

    local_ip = match.group("local_ip6") or match.group("local_ip4") or ""
    local_port = int(match.group("local_port"))
    src_ip = match.group("peer_ip6") or match.group("peer_ip4") or ""

    if not src_ip or not local_ip:
        return None

    return {
        "src_ip": src_ip,
        "dest_port": local_port,
        "protocol": "tcp",
    }


def is_whitelisted(ip: str, whitelist: list[str]) -> bool:
    """Return True if *ip* matches any entry in *whitelist* (exact IP or CIDR range)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in whitelist:
        entry = entry.strip()
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


class ConnectionMonitor(BaseMonitor):
    """Monitors inbound TCP connections for unknown source IPs (US-004).

    Polls ``ss -tnp`` at a configurable interval.  Connections from IPs not on
    the configured whitelist trigger a chat alert via the event bus.  Repeat
    connections from the same IP to the same port are suppressed within the
    configured cooldown window.
    """

    name = "connections"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        conn_repo: ConnectionRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._conn_repo = conn_repo
        self._startup_warning_logged = False

    async def _get_conn_repo(self) -> ConnectionRepository:
        if self._conn_repo is not None:
            return self._conn_repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.connection_repository import ConnectionRepository as _Repo

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        repo = _Repo(db)
        self._conn_repo = repo
        return repo

    async def collect(self) -> None:
        """Poll active inbound connections, track attempts, and emit threshold/digest alerts."""
        whitelist: list[str] = self.config.get("whitelist", [])

        if not whitelist and not self._startup_warning_logged:
            self.logger.warning(
                "No IP whitelist configured for connection monitoring — "
                "all inbound connections will generate alerts. "
                "Set monitors.connections.whitelist in config.yaml."
            )
            self._startup_warning_logged = True

        threshold_count: int = int(self.config.get("repeat_alert_count", 3))
        threshold_window_seconds = parse_duration_from_config(
            self.config,
            key="repeat_alert_window",
            default_seconds=10 * 60,
            logger=self.logger,
        )
        cooldown_seconds = parse_duration_from_config(
            self.config,
            key="cooldown",
            default_seconds=60 * 60,
            logger=self.logger,
        )
        threshold_window_minutes = int(threshold_window_seconds // 60)
        repo = await self._get_conn_repo()
        now = datetime.now(UTC)

        try:
            lines = await self._run_ss()
        except Exception:
            self.logger.exception("Failed to run ss command")
            return

        seen: set[tuple[str, int]] = set()
        affected_ips: dict[str, set[int]] = {}
        for line in lines:
            parsed = parse_ss_line(line)
            if parsed is None:
                continue

            src_ip: str = parsed["src_ip"]
            dest_port: int = parsed["dest_port"]
            protocol: str = parsed["protocol"]
            key = (src_ip, dest_port)

            if key in seen:
                continue
            seen.add(key)

            if is_whitelisted(src_ip, whitelist):
                continue

            await repo.record_attempt(src_ip, dest_port, protocol, now)
            affected_ips.setdefault(src_ip, set()).add(dest_port)

        window_start = now - timedelta(seconds=threshold_window_seconds)
        cooldown_cutoff = now - timedelta(seconds=cooldown_seconds)

        for src_ip, ports in affected_ips.items():
            count = await repo.count_attempts_since(src_ip, window_start)
            if count < threshold_count:
                continue

            last_alerted = await repo.get_last_alerted_for_ip(src_ip, "tcp")
            if last_alerted is not None and last_alerted > cooldown_cutoff:
                continue

            observed_ports = await repo.ports_since(src_ip, window_start)
            await self.ctx.event_bus.publish(
                "alert.connection.repeated_attempts_detected",
                {
                    "src_ip": src_ip,
                    "attempt_count": count,
                    "window_minutes": threshold_window_minutes,
                    "ports": observed_ports,
                    "timestamp": now.isoformat(),
                },
            )

            alert_port = min(ports)
            await repo.upsert(src_ip, alert_port, "tcp", now)
            self.logger.warning(
                "Connection attempt threshold exceeded: %d attempt(s) from %s in %d minutes",
                count,
                src_ip,
                threshold_window_minutes,
            )

        await self._maybe_send_daily_digest(repo, now)

    async def _maybe_send_daily_digest(self, repo: ConnectionRepository, now: datetime) -> None:
        """Send one daily connection digest at/after configured UTC time."""
        report_time = self._daily_report_time_utc()
        today = now.date()
        report_dt = datetime.combine(today, report_time, tzinfo=UTC)
        if now < report_dt:
            return

        state_key = "connections.daily_report.last_sent_date_utc"
        last_sent = await repo.get_state(state_key)
        if last_sent == today.isoformat():
            return

        since = now - timedelta(hours=24)
        rows = await repo.ip_port_activity_since(since)
        if rows:
            await self.ctx.event_bus.publish(
                "alert.connection.daily_digest",
                {
                    "timestamp": now.isoformat(),
                    "period_hours": 24,
                    "rows": rows,
                },
            )
        await repo.set_state(state_key, today.isoformat())

    def _daily_report_time_utc(self) -> time:
        """Return configured daily report UTC time, default 08:00."""
        raw = str(self.config.get("daily_report_time_utc", "08:00")).strip()
        if not re.fullmatch(r"\d{1,2}:\d{2}", raw):
            self.logger.warning("Invalid daily_report_time_utc %r; using default 08:00", raw)
            return time(hour=8, minute=0)
        hour_str, minute_str = raw.split(":")
        hour = int(hour_str)
        minute = int(minute_str)
        if hour < 0 or hour > 23 or minute < 0 or minute > 59:
            self.logger.warning("Out-of-range daily_report_time_utc %r; using default 08:00", raw)
            return time(hour=8, minute=0)
        return time(hour=hour, minute=minute)

    async def _run_ss(self) -> list[str]:
        """Run ``ss -tnp`` and return its output lines.  Runs in a thread pool."""
        import asyncio

        return await asyncio.to_thread(self._exec_ss)

    def _exec_ss(self) -> list[str]:
        import subprocess

        result = subprocess.run(
            ["ss", "-tnp"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"ss exited {result.returncode}: {result.stderr}")
        return result.stdout.splitlines()
