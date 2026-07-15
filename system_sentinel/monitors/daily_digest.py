from __future__ import annotations

from datetime import UTC, datetime, time, timedelta
import json
from typing import TYPE_CHECKING, Any

import psutil

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.db.login_repository import LoginRepository
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.aggregate_models import DailyAggregates

_LAST_SENT_DATE_STATE_KEY = "daily_digest.last_sent_date_local"
_LAST_SENT_TS_STATE_KEY = "daily_digest.last_sent_at_utc"


class DailyDigestMonitor(BaseMonitor):
    """Build and emit one daily digest event (US-010)."""

    name = "daily_digest"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        db: DatabaseConnection | None = None,
        metrics_repo: MetricsRepository | None = None,
        login_repo: LoginRepository | None = None,
        connection_repo: ConnectionRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._db = db
        self._metrics_repo = metrics_repo
        self._login_repo = login_repo
        self._connection_repo = connection_repo

    async def collect(self) -> None:
        now_local = self._now_local()
        report_time = self._send_time_local()
        report_dt = datetime.combine(now_local.date(), report_time, tzinfo=now_local.tzinfo)
        if now_local < report_dt:
            return

        connection_repo = await self._get_connection_repo()
        today_local = now_local.date().isoformat()
        if await connection_repo.get_state(_LAST_SENT_DATE_STATE_KEY) == today_local:
            return

        now_utc = self._now_utc()
        last_digest_raw = await connection_repo.get_state(_LAST_SENT_TS_STATE_KEY)
        if last_digest_raw is None:
            last_digest_at = now_utc - timedelta(hours=24)
        else:
            last_digest_at = datetime.fromisoformat(last_digest_raw)

        sections = await self._build_sections(now_utc, last_digest_at)
        await self.ctx.event_bus.publish(
            "alert.system.daily_digest",
            {"generated_at": now_utc.isoformat(), "sections": sections},
        )
        await connection_repo.set_state(_LAST_SENT_DATE_STATE_KEY, today_local)
        await connection_repo.set_state(_LAST_SENT_TS_STATE_KEY, now_utc.isoformat())

    async def _build_sections(self, now_utc: datetime, last_digest_at: datetime) -> dict[str, str]:
        window_start = now_utc - timedelta(hours=24)
        metrics_repo = await self._get_metrics_repo()
        login_repo = await self._get_login_repo()
        connection_repo = await self._get_connection_repo()
        aggregates = await metrics_repo.get_daily_aggregates(
            window_start=window_start,
            window_end=now_utc,
            collection_interval_seconds=self._collection_interval_seconds(),
        )

        return {
            "System Uptime": self._format_system_uptime(now_utc),
            "Update Status": await self._build_update_status(),
            "24h Resource Usage": self._build_resource_usage_summary(aggregates),
            "Failed SSH Logins (24h)": await self._build_login_summary(login_repo, window_start),
            "Unknown Inbound IPs (24h)": await self._build_connection_summary(
                connection_repo, window_start
            ),
            "Unknown Connection Intent (24h)": await self._build_connection_classification_summary(
                connection_repo, window_start
            ),
            "Files Auto-Deleted (24h)": "0 file(s) auto-deleted (auto-delete not enabled).",
            "Alerts Since Last Digest": await self._build_alerts_summary(last_digest_at),
        }

    def _format_system_uptime(self, now_utc: datetime) -> str:
        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
        uptime = now_utc - boot_time
        total_seconds = int(uptime.total_seconds())
        days, rem = divmod(total_seconds, 24 * 3600)
        hours, rem = divmod(rem, 3600)
        minutes, _seconds = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m"

    async def _build_update_status(self) -> str:
        db = await self._get_db()
        cursor = await db.connection.execute(
            """
            SELECT timestamp, description, details_json
            FROM audit_log
            WHERE action_type = 'tool_run'
              AND description LIKE 'Security update%'
            ORDER BY timestamp DESC
            LIMIT 1
            """
        )
        row = await cursor.fetchone()
        if row is None:
            return "No security update run recorded."

        timestamp = str(row[0])
        details: dict[str, Any] = {}
        if row[2]:
            parsed_raw = str(row[2])
            try:
                parsed = json.loads(parsed_raw)
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                details = parsed
        packages = details.get("packages_upgraded")
        package_count = len(packages) if isinstance(packages, list) else 0
        return (
            f"Last run: {timestamp}; packages updated: {package_count}; pending updates: unknown."
        )

    def _build_resource_usage_summary(self, aggregates: DailyAggregates) -> str:
        parts: list[str] = []

        cpu_part = "CPU avg n/a"
        if aggregates.cpu is not None:
            cpu_part = f"CPU avg {aggregates.cpu.average:.1f}%"
        parts.append(cpu_part)

        ram_part = "RAM peak n/a"
        if aggregates.ram is not None:
            ram_part = f"RAM peak {aggregates.ram.peak:.1f}%"
        parts.append(ram_part)

        if aggregates.disk:
            disk_parts = [
                f"{mount} peak {stats.peak:.1f}%"
                for mount, stats in sorted(aggregates.disk.items(), key=lambda item: item[0])
            ]
            disk_part = "Disk " + ", ".join(disk_parts)
        else:
            disk_part = "Disk n/a"
        parts.append(disk_part)

        if aggregates.gpu is not None:
            gpu_part = (
                f"GPU avg util {aggregates.gpu.utilization_percent.average:.1f}% "
                f"(peak {aggregates.gpu.utilization_percent.peak:.1f}%), "
                f"temp peak {aggregates.gpu.temperature_c.peak:.1f}°C"
            )
            if aggregates.gpu.vram_used_mb is not None and aggregates.gpu.vram_total_mb is not None:
                gpu_part = (
                    f"{gpu_part}, VRAM peak "
                    f"{aggregates.gpu.vram_used_mb.peak:.0f}/{aggregates.gpu.vram_total_mb.peak:.0f} MB"
                )
            if aggregates.gpu.power_draw_w is not None:
                gpu_part = f"{gpu_part}, power peak {aggregates.gpu.power_draw_w.peak:.1f} W"
            parts.append(gpu_part)

        if aggregates.gaps:
            total_gap_seconds = int(sum(g.duration_seconds for g in aggregates.gaps))
            gap_part = (
                f"Data gaps detected: {len(aggregates.gaps)} gap(s), "
                f"{self._format_duration_seconds(total_gap_seconds)} total."
            )
        else:
            gap_part = "No collection gaps detected."
        parts.append(gap_part)

        return "; ".join(parts)

    async def _build_login_summary(self, login_repo: LoginRepository, since: datetime) -> str:
        rows = await login_repo.unique_ips_since(since)
        attempts = sum(int(row["attempts"]) for row in rows)
        return f"{attempts} failed attempt(s) from {len(rows)} unique IP(s)."

    async def _build_connection_summary(
        self,
        connection_repo: ConnectionRepository,
        since: datetime,
    ) -> str:
        rows = await connection_repo.ip_port_activity_since(since)
        attempts = sum(int(row["attempts"]) for row in rows)
        unique_ips = len({str(row["ip_address"]) for row in rows})
        return f"{attempts} connection attempt(s) from {unique_ips} unknown IP(s)."

    async def _build_connection_classification_summary(
        self,
        connection_repo: ConnectionRepository,
        since: datetime,
    ) -> str:
        rows = await connection_repo.classification_activity_since(since)
        if not rows:
            return (
                "No classified connection activity in the last 24 hours "
                "(background_scan=0, suspicious=0, likely_access_attempt=0)."
            )

        counts = {
            "background_scan": 0,
            "suspicious": 0,
            "likely_access_attempt": 0,
        }
        ips_by_category: dict[str, dict[str, int]] = {
            "background_scan": {},
            "suspicious": {},
            "likely_access_attempt": {},
        }
        for row in rows:
            category = str(row["category"])
            ip = str(row["ip_address"])
            if category not in counts:
                continue
            counts[category] += 1
            ips_by_category[category][ip] = ips_by_category[category].get(ip, 0) + 1

        parts = [
            f"background_scan={counts['background_scan']}",
            f"suspicious={counts['suspicious']}",
            f"likely_access_attempt={counts['likely_access_attempt']}",
        ]

        top_lines: list[str] = []
        for category in ("background_scan", "suspicious", "likely_access_attempt"):
            ranked = sorted(
                ips_by_category[category].items(),
                key=lambda item: (-item[1], item[0]),
            )
            if not ranked:
                continue
            top_ip, hits = ranked[0]
            top_lines.append(f"{category} top: {top_ip} ({hits})")

        if not top_lines:
            return ", ".join(parts)
        return f"{', '.join(parts)}; {'; '.join(top_lines)}."

    async def _build_alerts_summary(self, since: datetime) -> str:
        db = await self._get_db()
        cursor = await db.connection.execute(
            """
            SELECT source, COUNT(*) AS count
            FROM audit_log
            WHERE action_type = 'alert_fired' AND timestamp > ?
            GROUP BY source
            ORDER BY count DESC, source ASC
            """,
            (since.isoformat(),),
        )
        rows = await cursor.fetchall()
        if not rows:
            return "No alerts fired since last digest."
        total = sum(int(row[1]) for row in rows)
        by_source = ", ".join(f"{row[0]} ({row[1]})" for row in rows)
        return f"{total} alert(s): {by_source}."

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

    async def _get_login_repo(self) -> LoginRepository:
        if self._login_repo is not None:
            return self._login_repo
        self._login_repo = LoginRepository(await self._get_db())
        return self._login_repo

    async def _get_connection_repo(self) -> ConnectionRepository:
        if self._connection_repo is not None:
            return self._connection_repo
        self._connection_repo = ConnectionRepository(await self._get_db())
        return self._connection_repo

    def _collection_interval_seconds(self) -> int:
        return int(
            parse_duration_from_config(
                self.config,
                key="expected_collection_interval",
                default_seconds=60,
                logger=self.logger,
            )
        )

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

    def _format_duration_seconds(self, total_seconds: int) -> str:
        days, rem = divmod(total_seconds, 24 * 3600)
        hours, rem = divmod(rem, 3600)
        minutes, _seconds = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m"
