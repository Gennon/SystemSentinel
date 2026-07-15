from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
from ipaddress import ip_address
import math
import re
import socket
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.geoip import choose_geoip_database_path, geoip_city_lat_lon
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
_ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted (\S+) for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+) port (\d+)"
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


def parse_successful_ssh_line(line: str) -> dict[str, Any] | None:
    """Parse a successful SSH login auth line and return extracted fields."""
    match = _ACCEPTED_LOGIN_RE.search(line)
    if match is None:
        return None
    auth_method, username, ip_address_str, port_str = match.groups()
    return {
        "username": username,
        "ip_address": ip_address_str,
        "port": int(port_str),
        "auth_method": auth_method,
    }


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_hhmm(value: object, default: time) -> time:
    if not isinstance(value, str):
        return default
    parsed = value.strip()
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", parsed)
    if match is None:
        return default
    hours = int(match.group(1))
    minutes = int(match.group(2))
    if hours < 0 or hours > 23 or minutes < 0 or minutes > 59:
        return default
    return time(hour=hours, minute=minutes)


def _is_time_within_window(current: time, start: time, end: time) -> bool:
    if start <= end:
        return start <= current <= end
    return current >= start or current <= end


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius_km * c


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
        self._last_alerted_at_by_ip: dict[str, datetime] = {}
        self._last_alerted_at_by_key: dict[str, datetime] = {}

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
        anomaly_cfg = _as_dict(self.config.get("anomaly_detection"))
        brute_force_enabled = bool(anomaly_cfg.get("brute_force_enabled", True))
        off_hours_enabled = bool(anomaly_cfg.get("off_hours_enabled", True))
        new_user_enabled = bool(anomaly_cfg.get("new_user_enabled", True))
        impossible_travel_enabled = bool(anomaly_cfg.get("impossible_travel_enabled", True))
        off_hours_start = _parse_hhmm(anomaly_cfg.get("off_hours_start"), default=time(7, 0))
        off_hours_end = _parse_hhmm(anomaly_cfg.get("off_hours_end"), default=time(22, 0))
        impossible_travel_window_seconds = parse_duration_from_config(
            anomaly_cfg,
            key="impossible_travel_window",
            default_seconds=2 * 60 * 60,
            logger=self.logger,
        )
        impossible_travel_min_distance_km = float(
            anomaly_cfg.get("impossible_travel_min_distance_km", 500.0)
        )
        geoip_database_path = choose_geoip_database_path(
            self.config.get("geoip_database_path"),
            anomaly_cfg.get("geoip_database_path"),
        )
        alert_count: int = int(self.config.get("failed_login_alert_count", 5))
        window_seconds = parse_duration_from_config(
            self.config,
            key="failed_login_window",
            default_seconds=10 * 60,
            logger=self.logger,
        )
        window_minutes = int(window_seconds // 60)
        cooldown_seconds = parse_duration_from_config(
            self.config,
            key="alert_cooldown",
            default_seconds=30 * 60,
            logger=self.logger,
        )
        now = datetime.now(UTC)
        window_start = now - timedelta(seconds=window_seconds)

        lines = await self._read_new_log_lines()
        affected_ips: set[str] = set()

        for line_index, line in enumerate(lines):
            observed_at = now + timedelta(microseconds=line_index)
            parsed = parse_failed_ssh_line(line)
            if parsed is not None:
                try:
                    await repo.record(
                        ip_address=parsed["ip_address"],
                        username=parsed["username"],
                        port=parsed["port"],
                        timestamp=observed_at,
                    )
                    affected_ips.add(parsed["ip_address"])
                except Exception:
                    self.logger.exception(
                        "Failed to record login attempt from %s", parsed["ip_address"]
                    )
                continue

            success = parse_successful_ssh_line(line)
            if success is None:
                continue

            username = str(success["username"])
            success_ip = str(success["ip_address"])
            success_port = int(success["port"])
            auth_method = str(success["auth_method"])
            was_known_user = await repo.has_successful_login(username, before=observed_at)
            impossible_travel_since = observed_at - timedelta(
                seconds=impossible_travel_window_seconds
            )
            previous_login = await repo.latest_successful_login_for_user(
                username,
                before=observed_at,
                since=impossible_travel_since,
            )
            await repo.record_successful_login(
                ip_address=success_ip,
                username=username,
                port=success_port,
                auth_method=auth_method,
                timestamp=observed_at,
            )

            if off_hours_enabled and not _is_time_within_window(
                observed_at.time(), off_hours_start, off_hours_end
            ):
                off_hours_payload = {
                    "anomaly_type": "off_hours",
                    "event_type": "successful_ssh_login",
                    "timestamp": observed_at.isoformat(),
                    "hostname": socket.gethostname(),
                    "username": username,
                    "ip_address": success_ip,
                    "port": success_port,
                    "auth_method": auth_method,
                    "allowed_hours": f"{off_hours_start:%H:%M}-{off_hours_end:%H:%M}",
                }
                await self._record_and_publish_anomaly(
                    repo=repo,
                    event_type="alert.login.off_hours_detected",
                    payload=off_hours_payload,
                    dedupe_key=f"off_hours:{username}:{success_ip}",
                    observed_at=observed_at,
                    cooldown_seconds=cooldown_seconds,
                )

            if new_user_enabled and not was_known_user:
                new_user_payload = {
                    "anomaly_type": "new_user",
                    "event_type": "successful_ssh_login",
                    "timestamp": observed_at.isoformat(),
                    "hostname": socket.gethostname(),
                    "username": username,
                    "ip_address": success_ip,
                    "port": success_port,
                    "auth_method": auth_method,
                }
                await self._record_and_publish_anomaly(
                    repo=repo,
                    event_type="alert.login.new_user_detected",
                    payload=new_user_payload,
                    dedupe_key=f"new_user:{username}",
                    observed_at=observed_at,
                    cooldown_seconds=0,
                )

            if (
                impossible_travel_enabled
                and previous_login is not None
                and previous_login["ip_address"] != success_ip
            ):
                previous_ip = str(previous_login["ip_address"])
                previous_timestamp = str(previous_login["timestamp"])
                distance_km = self._distance_between_ips_km(
                    previous_ip=previous_ip,
                    current_ip=success_ip,
                    geoip_database_path=geoip_database_path,
                )
                if (
                    distance_km is not None
                    and distance_km >= impossible_travel_min_distance_km
                    and not self._is_private_or_loopback_ip(success_ip)
                    and not self._is_private_or_loopback_ip(previous_ip)
                ):
                    impossible_payload = {
                        "anomaly_type": "impossible_travel",
                        "event_type": "successful_ssh_login",
                        "timestamp": observed_at.isoformat(),
                        "hostname": socket.gethostname(),
                        "username": username,
                        "ip_address": success_ip,
                        "port": success_port,
                        "auth_method": auth_method,
                        "previous_ip_address": previous_ip,
                        "previous_timestamp": previous_timestamp,
                        "distance_km": round(distance_km, 1),
                        "window_minutes": int(impossible_travel_window_seconds // 60),
                        "min_distance_km": impossible_travel_min_distance_km,
                    }
                    await self._record_and_publish_anomaly(
                        repo=repo,
                        event_type="alert.login.impossible_travel_detected",
                        payload=impossible_payload,
                        dedupe_key=f"impossible_travel:{username}",
                        observed_at=observed_at,
                        cooldown_seconds=cooldown_seconds,
                    )

        if not brute_force_enabled:
            return

        for ip in affected_ips:
            count = await repo.count_since(ip, window_start)
            if count < alert_count:
                continue
            last_alerted = self._last_alerted_at_by_ip.get(ip)
            if last_alerted is not None and (now - last_alerted).total_seconds() < cooldown_seconds:
                continue
            usernames = await repo.usernames_since(ip, window_start)
            payload = {
                "anomaly_type": "brute_force",
                "event_type": "failed_ssh_logins",
                "current_value": str(count),
                "threshold": f">={alert_count} attempts within {window_minutes} minutes",
                "timestamp": now.isoformat(),
                "hostname": socket.gethostname(),
                "username": ",".join(sorted(usernames)),
                "ip_address": ip,
                "attempt_count": count,
                "usernames": usernames,
                "window_minutes": window_minutes,
            }
            await self._record_and_publish_anomaly(
                repo=repo,
                event_type="alert.login.brute_force_detected",
                payload=payload,
                dedupe_key=f"brute_force:{ip}",
                observed_at=now,
                cooldown_seconds=cooldown_seconds,
            )
            self._last_alerted_at_by_ip[ip] = now
            self.logger.warning(
                "Brute-force alert: %d failed attempts from %s in %d minutes",
                count,
                ip,
                window_minutes,
            )

    async def _record_and_publish_anomaly(
        self,
        *,
        repo: LoginRepository,
        event_type: str,
        payload: dict[str, Any],
        dedupe_key: str,
        observed_at: datetime,
        cooldown_seconds: float,
    ) -> None:
        if cooldown_seconds > 0 and self._is_within_cooldown(
            dedupe_key=dedupe_key,
            now=observed_at,
            cooldown_seconds=cooldown_seconds,
        ):
            return
        username = str(payload.get("username", "unknown"))
        ip_address_value = str(payload.get("ip_address", "unknown"))
        anomaly_type = str(payload.get("anomaly_type", "unknown"))
        await repo.record_anomaly(
            observed_at=observed_at,
            anomaly_type=anomaly_type,
            username=username,
            ip_address=ip_address_value,
            details=payload,
        )
        await self.ctx.event_bus.publish(event_type, payload)
        self._last_alerted_at_by_key[dedupe_key] = observed_at

    def _is_within_cooldown(
        self, *, dedupe_key: str, now: datetime, cooldown_seconds: float
    ) -> bool:
        last_alerted = self._last_alerted_at_by_key.get(dedupe_key)
        if last_alerted is None:
            return False
        return (now - last_alerted).total_seconds() < cooldown_seconds

    def _distance_between_ips_km(
        self,
        *,
        previous_ip: str,
        current_ip: str,
        geoip_database_path: str,
    ) -> float | None:
        previous_location = geoip_city_lat_lon(previous_ip, geoip_database_path)
        current_location = geoip_city_lat_lon(current_ip, geoip_database_path)
        if previous_location is None or current_location is None:
            return None
        return _haversine_km(
            previous_location[0],
            previous_location[1],
            current_location[0],
            current_location[1],
        )

    def _is_private_or_loopback_ip(self, ip_address_str: str) -> bool:
        try:
            parsed = ip_address(ip_address_str)
        except ValueError:
            return True
        return bool(
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
            or parsed.is_unspecified
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
            self.logger.debug("journald not available, falling back to auth.log", exc_info=True)
        try:
            return await asyncio.to_thread(self._read_auth_log)
        except Exception:
            self.logger.warning(
                "Could not read any SSH auth log source. "
                "Ensure the sentinel user is a member of the 'systemd-journal' "
                "and 'adm' groups (run `sentinel setup` to fix).",
                exc_info=True,
            )
            return []

    def _read_journald(self) -> list[str]:
        import subprocess

        window_seconds = parse_duration_from_config(
            self.config,
            key="failed_login_window",
            default_seconds=10 * 60,
            logger=self.logger,
        )
        window_minutes = max(1, int(window_seconds // 60))
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
