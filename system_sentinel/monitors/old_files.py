from __future__ import annotations

import asyncio
from datetime import UTC, datetime, time, timedelta
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any

from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.old_files_repository import OldFilesRepository

_LAST_SCAN_STATE_KEY = "old_files.last_scan_at_utc"
_LAST_DIGEST_STATE_KEY = "old_files.daily_report.last_sent_date_utc"
_DEFAULT_SCAN_INTERVAL_SECONDS = 24 * 60 * 60


class OldFilesMonitor(BaseMonitor):
    """Scans watched directories for files older than the configured threshold (US-007)."""

    name = "old_files"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        old_files_repo: OldFilesRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._old_files_repo = old_files_repo
        self._startup_warning_logged = False

    async def _get_old_files_repo(self) -> OldFilesRepository:
        if self._old_files_repo is not None:
            return self._old_files_repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.old_files_repository import OldFilesRepository as _Repo

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        repo = _Repo(db)
        self._old_files_repo = repo
        return repo

    async def collect(self) -> None:
        watched_directories = self._watched_directories()
        if not watched_directories and not self._startup_warning_logged:
            self.logger.warning(
                "No watched_directories configured for old-file scanning. "
                "Set monitors.old_files.watched_directories in config.yaml."
            )
            self._startup_warning_logged = True

        repo = await self._get_old_files_repo()
        now = datetime.now(UTC)
        scan_interval_seconds = int(
            self.config.get("scan_interval_seconds", _DEFAULT_SCAN_INTERVAL_SECONDS)
        )
        age_threshold_days = int(self.config.get("age_threshold_days", 30))

        if watched_directories and await self._is_scan_due(repo, now, scan_interval_seconds):
            for directory in watched_directories:
                await self._scan_and_store(repo, directory, age_threshold_days, now)
            await repo.set_state(_LAST_SCAN_STATE_KEY, now.isoformat())

        await self._maybe_send_daily_digest(repo, now)

    def _watched_directories(self) -> list[str]:
        raw = self.config.get("watched_directories", [])
        if not isinstance(raw, list):
            return []
        normalized: list[str] = []
        for path in raw:
            raw_path = str(path).strip()
            if not raw_path:
                continue
            expanded = os.path.expandvars(raw_path)
            normalized.append(str(Path(expanded).expanduser()))
        return normalized

    async def _is_scan_due(
        self, repo: OldFilesRepository, now: datetime, scan_interval_seconds: int
    ) -> bool:
        if scan_interval_seconds <= 0:
            return True
        last_scan_raw = await repo.get_state(_LAST_SCAN_STATE_KEY)
        if last_scan_raw is None:
            return True
        last_scan = datetime.fromisoformat(last_scan_raw)
        return now >= last_scan + timedelta(seconds=scan_interval_seconds)

    async def _scan_and_store(
        self,
        repo: OldFilesRepository,
        directory: str,
        age_threshold_days: int,
        now: datetime,
    ) -> None:
        directory_path = Path(directory)
        if not directory_path.exists() or not directory_path.is_dir():
            self.logger.warning("Watched directory is missing or not a directory: %s", directory)
            return

        try:
            files = await asyncio.to_thread(
                self._scan_directory_sync, directory_path, age_threshold_days, now
            )
            await repo.record_scan(directory, age_threshold_days, now, files)
        except Exception:
            self.logger.exception("Failed old-file scan for watched directory %s", directory)

    def _scan_directory_sync(
        self,
        directory_path: Path,
        age_threshold_days: int,
        now: datetime,
    ) -> list[dict[str, Any]]:
        matched: list[dict[str, Any]] = []
        for path in directory_path.rglob("*"):
            if not path.is_file():
                continue
            try:
                stat_result = path.stat()
            except OSError:
                continue
            modified_at = datetime.fromtimestamp(stat_result.st_mtime, tz=UTC)
            age_days = int((now - modified_at).total_seconds() // 86400)
            if age_days < age_threshold_days:
                continue
            matched.append(
                {
                    "file_path": str(path),
                    "size_bytes": int(stat_result.st_size),
                    "last_modified": modified_at.isoformat(),
                    "age_days": age_days,
                }
            )
        return matched

    async def _maybe_send_daily_digest(self, repo: OldFilesRepository, now: datetime) -> None:
        report_time = self._daily_report_time_utc()
        today = now.date()
        report_dt = datetime.combine(today, report_time, tzinfo=UTC)
        if now < report_dt:
            return

        last_sent = await repo.get_state(_LAST_DIGEST_STATE_KEY)
        if last_sent == today.isoformat():
            return

        summaries = await repo.latest_scan_summaries(now - timedelta(hours=24))
        if summaries:
            await self.ctx.event_bus.publish(
                "alert.files.daily_digest",
                {
                    "timestamp": now.isoformat(),
                    "period_hours": 24,
                    "rows": summaries,
                },
            )
        await repo.set_state(_LAST_DIGEST_STATE_KEY, today.isoformat())

    def _daily_report_time_utc(self) -> time:
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
