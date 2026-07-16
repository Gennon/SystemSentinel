from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
import fnmatch
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, Protocol, cast

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.monitors.base import BaseMonitor


class _ObserverProtocol(Protocol):
    def schedule(self, event_handler: object, path: str, recursive: bool = False) -> object: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def join(self, timeout: float | None = None) -> None: ...


if TYPE_CHECKING:
    from asyncio import AbstractEventLoop

    from system_sentinel.core.context import AppContext
    from system_sentinel.db.directory_changes_repository import DirectoryChangesRepository

try:
    import pwd
except ImportError:  # pragma: no cover - non-POSIX fallback
    pwd = None  # type: ignore[assignment]

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer as WatchdogObserver

    _WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover - dependency is optional at runtime
    FileSystemEventHandler = object  # type: ignore[misc,assignment]
    WatchdogObserver = None  # type: ignore[assignment]
    _WATCHDOG_AVAILABLE = False

_DEFAULT_ALERT_COOLDOWN_SECONDS = 5 * 60


@dataclass(frozen=True)
class _WatchedDirectory:
    path: str
    whitelist_globs: tuple[str, ...]
    whitelist_regexes: tuple[re.Pattern[str], ...]


class _DirectoryEventHandler(FileSystemEventHandler):
    def __init__(self, monitor: DirectoryChangesMonitor) -> None:
        super().__init__()
        self._monitor = monitor

    def on_created(self, event: object) -> None:
        self._monitor.enqueue_change(
            change_type="created",
            file_path=str(getattr(event, "src_path", "")),
            destination_path=None,
            is_directory=bool(getattr(event, "is_directory", False)),
        )

    def on_deleted(self, event: object) -> None:
        self._monitor.enqueue_change(
            change_type="deleted",
            file_path=str(getattr(event, "src_path", "")),
            destination_path=None,
            is_directory=bool(getattr(event, "is_directory", False)),
        )

    def on_modified(self, event: object) -> None:
        self._monitor.enqueue_change(
            change_type="modified",
            file_path=str(getattr(event, "src_path", "")),
            destination_path=None,
            is_directory=bool(getattr(event, "is_directory", False)),
        )

    def on_moved(self, event: object) -> None:
        self._monitor.enqueue_change(
            change_type="renamed",
            file_path=str(getattr(event, "src_path", "")),
            destination_path=str(getattr(event, "dest_path", "")),
            is_directory=bool(getattr(event, "is_directory", False)),
        )


class DirectoryChangesMonitor(BaseMonitor):
    """Monitors configured directories and alerts on unexpected file changes (US-018)."""

    name = "directory_changes"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        directory_changes_repo: DirectoryChangesRepository | None = None,
        observer: _ObserverProtocol | None = None,
    ) -> None:
        super().__init__(config=config, app_ctx=app_ctx)
        self._repo = directory_changes_repo
        self._observer = observer
        self._loop: AbstractEventLoop | None = None
        self._started = False
        self._watched_directories: list[_WatchedDirectory] = []
        self._last_alerted_by_path: dict[str, datetime] = {}
        self._startup_warning_logged = False
        self._watchdog_unavailable_logged = False

    async def collect(self) -> None:
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        if self._started:
            return
        await self._start_observer()

    async def stop(self) -> None:
        if self._observer is None:
            return
        self._observer.stop()
        self._observer.join(timeout=2.0)

    def enqueue_change(
        self,
        *,
        change_type: str,
        file_path: str,
        destination_path: str | None,
        is_directory: bool,
    ) -> None:
        if is_directory:
            return
        if not file_path:
            return
        if self._loop is None:
            return
        observed_at = datetime.now(UTC)
        self._loop.call_soon_threadsafe(
            lambda: asyncio.create_task(
                self._handle_change(
                    observed_at=observed_at,
                    change_type=change_type,
                    file_path=file_path,
                    destination_path=destination_path,
                )
            )
        )

    async def _start_observer(self) -> None:
        self._watched_directories = self._load_watched_directories()
        if not self._watched_directories:
            if not self._startup_warning_logged:
                self.logger.warning(
                    "No monitored directories configured for directory-change alerts. "
                    "Set monitors.directory_changes.watched_directories in config.yaml."
                )
                self._startup_warning_logged = True
            return
        if not _WATCHDOG_AVAILABLE:
            if not self._watchdog_unavailable_logged:
                self.logger.error(
                    "watchdog dependency unavailable. Install with `pip install watchdog` "
                    "to enable directory-change alerts."
                )
                self._watchdog_unavailable_logged = True
            return
        if self._observer is None:
            self._observer = cast("_ObserverProtocol", WatchdogObserver())
        observer = self._observer
        if observer is None:
            return
        handler = _DirectoryEventHandler(self)
        scheduled_any = False
        for watched in self._watched_directories:
            if not os.path.isdir(watched.path):
                self.logger.warning(
                    "Monitored directory is missing or not a directory: %s",
                    watched.path,
                )
                continue
            observer.schedule(handler, watched.path, recursive=True)
            scheduled_any = True
        if not scheduled_any:
            return
        observer.start()
        self._started = True
        self.logger.info(
            "Directory-change monitor started for %d path(s).",
            len(self._watched_directories),
        )

    async def _handle_change(
        self,
        *,
        observed_at: datetime,
        change_type: str,
        file_path: str,
        destination_path: str | None,
    ) -> None:
        watched = self._find_watched_directory(
            file_path=file_path, destination_path=destination_path
        )
        if watched is None:
            return
        canonical_path = self._canonical_alert_path(change_type, file_path, destination_path)
        if self._is_whitelisted(watched, canonical_path, file_path, destination_path):
            await self._record_event(
                observed_at=observed_at,
                watched_directory=watched.path,
                change_type=change_type,
                file_path=canonical_path,
                destination_path=destination_path,
                process_owner=self._determine_process_owner(canonical_path),
                alert_suppressed=True,
                suppression_reason="whitelist",
            )
            return

        process_owner = self._determine_process_owner(canonical_path)
        is_cooldown_active = self._is_cooldown_active(canonical_path, observed_at)
        await self._record_event(
            observed_at=observed_at,
            watched_directory=watched.path,
            change_type=change_type,
            file_path=canonical_path,
            destination_path=destination_path,
            process_owner=process_owner,
            alert_suppressed=is_cooldown_active,
            suppression_reason="cooldown" if is_cooldown_active else None,
        )
        if is_cooldown_active:
            return

        self._last_alerted_by_path[canonical_path] = observed_at
        await self.ctx.event_bus.publish(
            "alert.files.change_detected",
            {
                "event_type": "directory_change_detected",
                "watched_directory": watched.path,
                "file_path": canonical_path,
                "change_type": change_type,
                "timestamp": observed_at.isoformat(),
                "process_owner": process_owner or "unknown",
                "destination_path": destination_path,
            },
        )

    def _load_watched_directories(self) -> list[_WatchedDirectory]:
        raw = self.config.get("watched_directories", [])
        if not isinstance(raw, list):
            return []
        watched_directories: list[_WatchedDirectory] = []
        for item in raw:
            if isinstance(item, str):
                path = self._normalize_path(item)
                if path:
                    watched_directories.append(
                        _WatchedDirectory(path=path, whitelist_globs=(), whitelist_regexes=())
                    )
                continue
            if not isinstance(item, dict):
                continue
            path_raw = str(item.get("path", "")).strip()
            path = self._normalize_path(path_raw)
            if not path:
                continue
            globs_raw = item.get("whitelist_globs", [])
            globs = (
                tuple(str(pattern) for pattern in globs_raw if str(pattern).strip())
                if isinstance(globs_raw, list)
                else ()
            )
            regexes = self._compile_regex_whitelist(item.get("whitelist_regex", []), path=path)
            watched_directories.append(
                _WatchedDirectory(path=path, whitelist_globs=globs, whitelist_regexes=regexes)
            )
        return watched_directories

    def _normalize_path(self, raw_path: str) -> str:
        path = raw_path.strip()
        if not path:
            return ""
        expanded = os.path.expandvars(path)
        return str(Path(expanded).expanduser())

    def _compile_regex_whitelist(self, raw: object, *, path: str) -> tuple[re.Pattern[str], ...]:
        if not isinstance(raw, list):
            return ()
        compiled: list[re.Pattern[str]] = []
        for pattern in raw:
            text = str(pattern).strip()
            if not text:
                continue
            try:
                compiled.append(re.compile(text))
            except re.error:
                self.logger.warning(
                    "Ignoring invalid whitelist regex for %s: %r",
                    path,
                    text,
                )
        return tuple(compiled)

    def _find_watched_directory(
        self, *, file_path: str, destination_path: str | None
    ) -> _WatchedDirectory | None:
        matches: list[tuple[int, _WatchedDirectory]] = []
        for watched in self._watched_directories:
            for candidate in (file_path, destination_path):
                if not candidate:
                    continue
                if self._is_within(candidate, watched.path):
                    matches.append((len(watched.path), watched))
                    break
        if not matches:
            return None
        matches.sort(key=lambda item: item[0], reverse=True)
        return matches[0][1]

    def _is_within(self, candidate_path: str, watched_path: str) -> bool:
        try:
            candidate_abs = str(Path(candidate_path).resolve(strict=False))
            watched_abs = str(Path(watched_path).resolve(strict=False))
            return os.path.commonpath([candidate_abs, watched_abs]) == watched_abs
        except ValueError:
            return False

    def _canonical_alert_path(
        self, change_type: str, file_path: str, destination_path: str | None
    ) -> str:
        if change_type == "renamed" and destination_path:
            return destination_path
        return file_path

    def _is_whitelisted(
        self,
        watched: _WatchedDirectory,
        canonical_path: str,
        file_path: str,
        destination_path: str | None,
    ) -> bool:
        if not watched.whitelist_globs and not watched.whitelist_regexes:
            return False
        candidates = [canonical_path, file_path]
        if destination_path:
            candidates.append(destination_path)
        for candidate in candidates:
            base_name = Path(candidate).name
            for pattern in watched.whitelist_globs:
                if fnmatch.fnmatch(candidate, pattern) or fnmatch.fnmatch(base_name, pattern):
                    return True
            for regex in watched.whitelist_regexes:
                if regex.search(candidate):
                    return True
        return False

    def _cooldown_seconds(self) -> float:
        return parse_duration_from_config(
            self.config,
            key="alert_cooldown",
            default_seconds=_DEFAULT_ALERT_COOLDOWN_SECONDS,
            logger=self.logger,
        )

    def _is_cooldown_active(self, file_path: str, observed_at: datetime) -> bool:
        cooldown_seconds = self._cooldown_seconds()
        if cooldown_seconds <= 0:
            return False
        last_alerted = self._last_alerted_by_path.get(file_path)
        if last_alerted is None:
            return False
        return (observed_at - last_alerted).total_seconds() < cooldown_seconds

    async def _record_event(
        self,
        *,
        observed_at: datetime,
        watched_directory: str,
        change_type: str,
        file_path: str,
        destination_path: str | None,
        process_owner: str | None,
        alert_suppressed: bool,
        suppression_reason: str | None,
    ) -> None:
        repo = await self._get_repo()
        await repo.record_event(
            observed_at=observed_at,
            watched_directory=watched_directory,
            change_type=change_type,
            file_path=file_path,
            destination_path=destination_path,
            process_owner=process_owner,
            alert_suppressed=alert_suppressed,
            suppression_reason=suppression_reason,
        )

    async def _get_repo(self) -> DirectoryChangesRepository:
        if self._repo is not None:
            return self._repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.directory_changes_repository import (
            DirectoryChangesRepository as _Repo,
        )

        data_dir = str(self.config.get("data_dir", "/var/lib/sentinel"))
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        repo = _Repo(db)
        self._repo = repo
        return repo

    def _determine_process_owner(self, file_path: str) -> str | None:
        if pwd is None:
            return None
        try:
            stat_result = os.stat(file_path)
            return pwd.getpwuid(stat_result.st_uid).pw_name
        except (KeyError, OSError):
            return None
