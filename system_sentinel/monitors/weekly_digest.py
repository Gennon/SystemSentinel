from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
import json
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext

_LAST_SENT_WEEK_STATE_KEY = "weekly_digest.last_sent_week_local"
_LAST_SENT_TS_STATE_KEY = "weekly_digest.last_sent_at_utc"
_DEFAULT_SEND_DAY = "monday"
_DAY_TO_WEEKDAY = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


class WeeklyDigestMonitor(BaseMonitor):
    """Build and emit one weekly digest event (US-031)."""

    name = "weekly_digest"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        db: DatabaseConnection | None = None,
        metrics_repo: MetricsRepository | None = None,
        connection_repo: ConnectionRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._db = db
        self._metrics_repo = metrics_repo
        self._connection_repo = connection_repo

    async def collect(self) -> None:
        now_local = self._now_local()
        report_weekday = self._send_weekday_local()
        report_time = self._send_time_local()
        report_dt = datetime.combine(now_local.date(), report_time, tzinfo=now_local.tzinfo)
        if now_local.weekday() != report_weekday or now_local < report_dt:
            return

        connection_repo = await self._get_connection_repo()
        iso = now_local.isocalendar()
        current_week_key = f"{iso.year}-W{iso.week:02d}"
        if await connection_repo.get_state(_LAST_SENT_WEEK_STATE_KEY) == current_week_key:
            return

        now_utc = self._now_utc()
        sections = await self._build_sections(now_utc)
        await self.ctx.event_bus.publish(
            "alert.system.weekly_digest",
            {"generated_at": now_utc.isoformat(), "sections": sections},
        )
        await connection_repo.set_state(_LAST_SENT_WEEK_STATE_KEY, current_week_key)
        await connection_repo.set_state(_LAST_SENT_TS_STATE_KEY, now_utc.isoformat())

    async def _build_sections(self, now_utc: datetime) -> dict[str, str]:
        week_start = now_utc - timedelta(days=7)
        previous_week_start = now_utc - timedelta(days=14)
        previous_week_end = week_start
        metrics_repo = await self._get_metrics_repo()
        current_aggregates = await metrics_repo.get_daily_aggregates(
            window_start=week_start,
            window_end=now_utc,
            collection_interval_seconds=self._collection_interval_seconds(),
        )
        previous_aggregates = await metrics_repo.get_daily_aggregates(
            window_start=previous_week_start,
            window_end=previous_week_end,
            collection_interval_seconds=self._collection_interval_seconds(),
        )
        return {
            "Storage Usage Trend (7d)": await self._build_storage_usage_trend(
                metrics_repo=metrics_repo,
                week_start=week_start,
                week_end=now_utc,
                previous_week_start=previous_week_start,
                previous_week_end=previous_week_end,
            ),
            "Login Summary (7d)": await self._build_login_summary(week_start),
            "Resource Averages vs Previous Week": self._build_resource_delta_summary(
                current_aggregates=current_aggregates,
                previous_aggregates=previous_aggregates,
            ),
            "Update History (7d)": await self._build_update_history(week_start),
            "File Cleanup Summary (7d)": await self._build_cleanup_summary(week_start),
            "Security Posture (7d)": await self._build_security_posture(
                week_start=week_start,
                previous_week_start=previous_week_start,
                previous_week_end=previous_week_end,
            ),
        }

    async def _build_storage_usage_trend(
        self,
        *,
        metrics_repo: MetricsRepository,
        week_start: datetime,
        week_end: datetime,
        previous_week_start: datetime,
        previous_week_end: datetime,
    ) -> str:
        current_week_samples = await metrics_repo.query_range("disk", week_start, week_end)
        previous_week_samples = await metrics_repo.query_range(
            "disk", previous_week_start, previous_week_end
        )
        current_deltas = self._disk_used_bytes_delta(current_week_samples)
        previous_deltas = self._disk_used_bytes_delta(previous_week_samples)
        mountpoints = sorted(set(current_deltas) | set(previous_deltas))
        if not mountpoints:
            return "No disk usage samples recorded for the last 7 days."

        lines: list[str] = []
        for mountpoint in mountpoints:
            current_delta = current_deltas.get(mountpoint, 0)
            previous_delta = previous_deltas.get(mountpoint, 0)
            delta_vs_last_week = self._relative_delta_percent(current_delta, previous_delta)
            delta_vs_last_week_label = (
                f"{delta_vs_last_week:+.1f}%"
                if delta_vs_last_week is not None
                else "n/a (no prior-week baseline)"
            )
            lines.append(
                f"{mountpoint}: {self._format_bytes_signed(current_delta)} disk used, "
                f"{delta_vs_last_week_label} vs last week"
            )
        return "; ".join(lines)

    async def _build_login_summary(self, week_start: datetime) -> str:
        db = await self._get_db()

        failed_logins = await self._count_query(
            db,
            "SELECT COUNT(*) FROM login_attempts WHERE timestamp >= ?",
            (week_start.isoformat(),),
        )
        successful_logins = await self._count_query(
            db,
            "SELECT COUNT(*) FROM login_successes WHERE timestamp >= ?",
            (week_start.isoformat(),),
        )
        unique_ips = await self._count_query(
            db,
            """
            SELECT COUNT(*) FROM (
                SELECT ip_address FROM login_attempts WHERE timestamp >= ?
                UNION
                SELECT ip_address FROM login_successes WHERE timestamp >= ?
            )
            """,
            (week_start.isoformat(), week_start.isoformat()),
        )
        anomalies = await self._count_query(
            db,
            "SELECT COUNT(*) FROM login_anomalies WHERE observed_at >= ?",
            (week_start.isoformat(),),
        )

        return (
            f"successful={successful_logins}, failed={failed_logins}, "
            f"unique_ips={unique_ips}, anomalies={anomalies}"
        )

    def _build_resource_delta_summary(
        self, *, current_aggregates: Any, previous_aggregates: Any
    ) -> str:
        cpu_line = self._format_percent_metric_delta(
            label="CPU avg",
            current=self._aggregate_value(current_aggregates.cpu, "average"),
            previous=self._aggregate_value(previous_aggregates.cpu, "average"),
        )
        ram_line = self._format_percent_metric_delta(
            label="RAM avg",
            current=self._aggregate_value(current_aggregates.ram, "average"),
            previous=self._aggregate_value(previous_aggregates.ram, "average"),
        )
        disk_current = self._average_disk_percent(current_aggregates.disk)
        disk_previous = self._average_disk_percent(previous_aggregates.disk)
        disk_line = self._format_percent_metric_delta(
            label="Disk avg",
            current=disk_current,
            previous=disk_previous,
        )
        return "; ".join([cpu_line, ram_line, disk_line])

    async def _build_update_history(self, week_start: datetime) -> str:
        db = await self._get_db()
        cursor = await db.connection.execute(
            """
            SELECT details_json
            FROM audit_log
            WHERE action_type = 'tool_run'
              AND description LIKE 'Security update%'
              AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (week_start.isoformat(),),
        )
        rows = list(await cursor.fetchall())
        if not rows:
            return "No security update runs recorded this week."

        total_upgrades = 0
        packages: dict[str, int] = {}
        for row in rows:
            details = self._parse_json_dict(row[0])
            upgraded = details.get("packages_upgraded")
            if not isinstance(upgraded, list):
                continue
            total_upgrades += len(upgraded)
            for package in upgraded:
                package_name = str(package).strip()
                if not package_name:
                    continue
                packages[package_name] = packages.get(package_name, 0) + 1

        top_packages = ", ".join(
            f"{name} ({count})"
            for name, count in sorted(packages.items(), key=lambda item: (-item[1], item[0]))[:5]
        )
        package_summary = top_packages if top_packages else "none"
        return (
            f"{len(rows)} run(s), {total_upgrades} package upgrade(s); "
            f"top updated packages: {package_summary}"
        )

    async def _build_cleanup_summary(self, week_start: datetime) -> str:
        db = await self._get_db()
        cursor = await db.connection.execute(
            """
            SELECT details_json
            FROM audit_log
            WHERE action_type = 'chat_command'
              AND timestamp >= ?
            ORDER BY timestamp ASC
            """,
            (week_start.isoformat(),),
        )
        rows = await cursor.fetchall()
        runs = 0
        deleted_files = 0
        reclaimed_bytes = 0
        failed_deletions = 0
        for row in rows:
            details = self._parse_json_dict(row[0])
            if str(details.get("command")) != "!cleanup":
                continue
            cleanup = details.get("cleanup")
            if not isinstance(cleanup, dict):
                continue
            runs += 1
            deleted_files += int(cleanup.get("deleted_files", 0))
            reclaimed_bytes += int(cleanup.get("reclaimed_bytes", 0))
            failed_deletions += int(cleanup.get("failed_deletions", 0))

        if runs == 0:
            return "No cleanup runs with deletion metrics recorded this week."
        return (
            f"runs={runs}, deleted={deleted_files} file(s), "
            f"reclaimed={self._format_bytes_unsigned(reclaimed_bytes)}, failed={failed_deletions}"
        )

    async def _build_security_posture(
        self,
        *,
        week_start: datetime,
        previous_week_start: datetime,
        previous_week_end: datetime,
    ) -> str:
        hardening = await self._build_hardening_posture(week_start)
        vulnscan = await self._build_vulnerability_delta(
            week_start, previous_week_start, previous_week_end
        )
        return f"{hardening}; {vulnscan}"

    async def _build_hardening_posture(self, week_start: datetime) -> str:
        db = await self._get_db()
        cursor = await db.connection.execute(
            """
            SELECT outcome, details_json
            FROM audit_log
            WHERE action_type = 'tool_run'
              AND timestamp >= ?
              AND details_json LIKE '%"tool": "hardening"%'
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (week_start.isoformat(),),
        )
        row = await cursor.fetchone()
        if row is None:
            return "hardening: no audit run recorded this week"

        outcome = str(row[0])
        details = self._parse_json_dict(row[1])
        failed_checks = details.get("failed_checks")
        remediated_checks = details.get("remediated_checks")
        failed_count = len(failed_checks) if isinstance(failed_checks, list) else 0
        remediated_count = len(remediated_checks) if isinstance(remediated_checks, list) else 0
        return (
            f"hardening: {outcome} "
            f"(failed_checks={failed_count}, remediated_checks={remediated_count})"
        )

    async def _build_vulnerability_delta(
        self,
        week_start: datetime,
        previous_week_start: datetime,
        previous_week_end: datetime,
    ) -> str:
        current = await self._latest_vulnscan_count(week_start, None)
        if current is None:
            return "vulnscan: not run this week"
        previous = await self._latest_vulnscan_count(previous_week_start, previous_week_end)
        if previous is None:
            return f"vulnscan: findings={current} (no previous-week baseline)"
        delta = current - previous
        return f"vulnscan: findings={current}, delta={delta:+d} vs last week"

    async def _latest_vulnscan_count(self, since: datetime, until: datetime | None) -> int | None:
        db = await self._get_db()
        query = """
            SELECT details_json
            FROM audit_log
            WHERE action_type = 'tool_run'
              AND timestamp >= ?
              AND details_json LIKE '%"tool": "vulnscan"%'
        """
        params: list[str] = [since.isoformat()]
        if until is not None:
            query += " AND timestamp < ?"
            params.append(until.isoformat())
        query += " ORDER BY timestamp DESC LIMIT 1"
        cursor = await db.connection.execute(query, tuple(params))
        row = await cursor.fetchone()
        if row is None:
            return None
        details = self._parse_json_dict(row[0])
        for key in ("vulnerability_count", "vulnerabilities", "warning_count", "warnings"):
            raw = details.get(key)
            if isinstance(raw, int):
                return raw
            if isinstance(raw, float):
                return int(raw)
            if isinstance(raw, str) and raw.strip().isdigit():
                return int(raw.strip())
        return None

    def _disk_used_bytes_delta(self, samples: list[dict[str, Any]]) -> dict[str, int]:
        deltas: dict[str, int] = {}
        first_seen: dict[str, int] = {}
        last_seen: dict[str, int] = {}
        for sample in samples:
            partitions = sample.get("partitions")
            if not isinstance(partitions, list):
                continue
            for partition in partitions:
                if not isinstance(partition, dict):
                    continue
                mountpoint = str(partition.get("mountpoint", "")).strip()
                used_bytes_raw = partition.get("used_bytes")
                if not mountpoint or not isinstance(used_bytes_raw, (int, float)):
                    continue
                used_bytes = int(used_bytes_raw)
                if mountpoint not in first_seen:
                    first_seen[mountpoint] = used_bytes
                last_seen[mountpoint] = used_bytes
        for mountpoint, first in first_seen.items():
            deltas[mountpoint] = last_seen.get(mountpoint, first) - first
        return deltas

    def _average_disk_percent(self, disk: dict[str, Any]) -> float | None:
        if not disk:
            return None
        values = [float(stats.average) for stats in disk.values()]
        if not values:
            return None
        return sum(values) / len(values)

    def _aggregate_value(self, aggregate: Any, attr_name: str) -> float | None:
        if aggregate is None:
            return None
        raw = getattr(aggregate, attr_name, None)
        if raw is None:
            return None
        return float(raw)

    def _format_percent_metric_delta(
        self,
        *,
        label: str,
        current: float | None,
        previous: float | None,
    ) -> str:
        if current is None:
            return f"{label} n/a"
        delta_percent = self._relative_delta_percent(current, previous)
        if delta_percent is None:
            return f"{label} {current:.1f}% (no previous-week baseline)"
        return f"{label} {current:.1f}% ({delta_percent:+.1f}% vs last week)"

    def _relative_delta_percent(self, current: float, previous: float | None) -> float | None:
        if previous is None or previous == 0:
            return None
        return ((current - previous) / abs(previous)) * 100.0

    def _parse_json_dict(self, raw: object) -> dict[str, Any]:
        if not isinstance(raw, str):
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
        return {}

    def _collection_interval_seconds(self) -> int:
        return int(
            parse_duration_from_config(
                self.config,
                key="expected_collection_interval",
                default_seconds=60,
                logger=self.logger,
            )
        )

    def _send_weekday_local(self) -> int:
        raw = str(self.config.get("send_day_local", _DEFAULT_SEND_DAY)).strip().lower()
        if raw in _DAY_TO_WEEKDAY:
            return _DAY_TO_WEEKDAY[raw]
        self.logger.warning("Invalid send_day_local %r; using default Monday", raw)
        return _DAY_TO_WEEKDAY[_DEFAULT_SEND_DAY]

    def _send_time_local(self) -> time:
        raw = str(self.config.get("send_time_local", "08:00")).strip()
        if len(raw.split(":")) != 2:
            self.logger.warning("Invalid send_time_local %r; using default 08:00", raw)
            return time(hour=8, minute=0)
        hour_str, minute_str = raw.split(":")
        if not hour_str.isdigit() or not minute_str.isdigit():
            self.logger.warning("Invalid send_time_local %r; using default 08:00", raw)
            return time(hour=8, minute=0)
        hour = int(hour_str)
        minute = int(minute_str)
        if hour < 0 or hour > 23 or minute < 0 or minute > 59:
            self.logger.warning("Out-of-range send_time_local %r; using default 08:00", raw)
            return time(hour=8, minute=0)
        return time(hour=hour, minute=minute)

    def _now_local(self) -> datetime:
        return datetime.now().astimezone()

    def _now_utc(self) -> datetime:
        return datetime.now(UTC)

    async def _get_db(self) -> DatabaseConnection:
        if self._db is not None:
            return self._db
        data_dir = str(self.config.get("data_dir", "/var/lib/sentinel"))
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        self._db = db
        return db

    async def _get_metrics_repo(self) -> MetricsRepository:
        if self._metrics_repo is not None:
            return self._metrics_repo
        self._metrics_repo = MetricsRepository(await self._get_db())
        return self._metrics_repo

    async def _get_connection_repo(self) -> ConnectionRepository:
        if self._connection_repo is not None:
            return self._connection_repo
        self._connection_repo = ConnectionRepository(await self._get_db())
        return self._connection_repo

    async def _count_query(
        self,
        db: DatabaseConnection,
        query: str,
        params: tuple[str, ...],
    ) -> int:
        cursor = await db.connection.execute(query, params)
        row = await cursor.fetchone()
        if row is None:
            return 0
        return int(row[0])

    def _format_bytes_signed(self, value: int) -> str:
        sign = "+" if value >= 0 else "-"
        return f"{sign}{self._format_bytes_unsigned(abs(value))}"

    def _format_bytes_unsigned(self, value: int) -> str:
        size = float(value)
        units = ("B", "KB", "MB", "GB", "TB", "PB")
        unit_index = 0
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        display = f"{size:.1f}".rstrip("0").rstrip(".")
        return f"{display} {units[unit_index]}"
