from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.file_integrity import expand_monitored_targets, normalize_monitored_paths
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.file_integrity_repository import FileIntegrityRepository
    from system_sentinel.file_integrity import MonitoredFileTarget

_LAST_VERIFICATION_STATE_KEY = "file_integrity.last_verification_at_utc"
_DEFAULT_VERIFY_INTERVAL_SECONDS = 10 * 60


class FileIntegrityMonitor(BaseMonitor):
    """Verifies SHA-256 baselines for monitored files and alerts on mismatch (US-030)."""

    name = "file_integrity"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        file_integrity_repo: FileIntegrityRepository | None = None,
    ) -> None:
        super().__init__(config=config, app_ctx=app_ctx)
        self._repo = file_integrity_repo
        self._startup_warning_logged = False

    async def collect(self) -> None:
        monitored_paths = normalize_monitored_paths(self.config.get("monitored_paths"))
        targets = expand_monitored_targets(monitored_paths)
        if not targets and not self._startup_warning_logged:
            self.logger.warning(
                "No monitored paths configured for file integrity checks. "
                "Set monitors.file_integrity.monitored_paths in config.yaml."
            )
            self._startup_warning_logged = True

        repo = await self._get_repo()
        now = datetime.now(UTC)
        verify_interval = parse_duration_from_config(
            self.config,
            key="verify_interval",
            default_seconds=_DEFAULT_VERIFY_INTERVAL_SECONDS,
            logger=self.logger,
        )
        if not await self._is_verification_due(repo, now, verify_interval):
            return

        for target in targets:
            await self._verify_target(repo=repo, target=target, checked_at=now)
        await repo.set_state(_LAST_VERIFICATION_STATE_KEY, now.isoformat())

    async def _get_repo(self) -> FileIntegrityRepository:
        if self._repo is not None:
            return self._repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.file_integrity_repository import (
            FileIntegrityRepository as _FileIntegrityRepository,
        )

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        self._repo = _FileIntegrityRepository(db)
        return self._repo

    async def _is_verification_due(
        self,
        repo: FileIntegrityRepository,
        now: datetime,
        verify_interval_seconds: float,
    ) -> bool:
        if verify_interval_seconds <= 0:
            return True
        last_verification_raw = await repo.get_state(_LAST_VERIFICATION_STATE_KEY)
        if last_verification_raw is None:
            return True
        last_verification = datetime.fromisoformat(last_verification_raw)
        return now >= last_verification + timedelta(seconds=verify_interval_seconds)

    async def _verify_target(
        self,
        *,
        repo: FileIntegrityRepository,
        target: MonitoredFileTarget,
        checked_at: datetime,
    ) -> None:
        baseline = await repo.get_baseline(target.path)
        path_obj = Path(target.path)
        if not path_obj.exists() or not path_obj.is_file():
            if baseline is None:
                return
            expected_hash = str(baseline.get("expected_sha256", ""))
            await repo.record_verification(
                path=target.path,
                checked_at=checked_at,
                expected_sha256=expected_hash,
                actual_sha256="MISSING",
                status="mismatch",
            )
            await self._publish_mismatch_alert(
                checked_at=checked_at,
                file_path=target.path,
                expected_hash=expected_hash,
                actual_hash="MISSING",
            )
            return

        actual_hash = _sha256_file(path_obj)
        if baseline is None:
            await repo.upsert_baseline(
                path=target.path,
                source_path=target.source_path,
                expected_sha256=actual_hash,
                observed_at=checked_at,
            )
            await repo.record_verification(
                path=target.path,
                checked_at=checked_at,
                expected_sha256=actual_hash,
                actual_sha256=actual_hash,
                status="baseline_created",
            )
            return

        expected_hash = str(baseline.get("expected_sha256", ""))
        status = "ok" if expected_hash == actual_hash else "mismatch"
        await repo.record_verification(
            path=target.path,
            checked_at=checked_at,
            expected_sha256=expected_hash,
            actual_sha256=actual_hash,
            status=status,
        )
        if status == "mismatch":
            await self._publish_mismatch_alert(
                checked_at=checked_at,
                file_path=target.path,
                expected_hash=expected_hash,
                actual_hash=actual_hash,
            )

    async def _publish_mismatch_alert(
        self,
        *,
        checked_at: datetime,
        file_path: str,
        expected_hash: str,
        actual_hash: str,
    ) -> None:
        await self.ctx.event_bus.publish(
            "alert.files.integrity_mismatch",
            {
                "event_type": "file_integrity_mismatch",
                "file_path": file_path,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "timestamp": checked_at.isoformat(),
            },
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
