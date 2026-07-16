from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import logging
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.monitors.directory_changes import DirectoryChangesMonitor

if TYPE_CHECKING:
    from pathlib import Path

    from system_sentinel.db.directory_changes_repository import DirectoryChangesRepository


@dataclass
class _RecordedEvent:
    watched_directory: str
    change_type: str
    file_path: str
    destination_path: str | None
    process_owner: str | None
    alert_suppressed: bool
    suppression_reason: str | None


class _FakeDirectoryChangesRepository:
    def __init__(self) -> None:
        self.recorded: list[_RecordedEvent] = []

    async def record_event(
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
        _ = observed_at
        self.recorded.append(
            _RecordedEvent(
                watched_directory=watched_directory,
                change_type=change_type,
                file_path=file_path,
                destination_path=destination_path,
                process_owner=process_owner,
                alert_suppressed=alert_suppressed,
                suppression_reason=suppression_reason,
            )
        )


def _make_ctx() -> AppContext:
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=AsyncMock(),
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


def _monitor(
    tmp_path: Path,
    repo: DirectoryChangesRepository,
    *,
    watched_directories: list[object] | None = None,
    alert_cooldown: str = "00:05:00",
) -> DirectoryChangesMonitor:
    config: dict[str, object] = {
        "enabled": True,
        "watched_directories": watched_directories or [str(tmp_path)],
        "alert_cooldown": alert_cooldown,
    }
    monitor = DirectoryChangesMonitor(
        config=config, app_ctx=_make_ctx(), directory_changes_repo=repo
    )
    monitor._watched_directories = monitor._load_watched_directories()
    return monitor


@pytest.mark.asyncio
async def test_handle_change_records_and_publishes_alert(tmp_path: Path) -> None:
    repo = _FakeDirectoryChangesRepository()
    monitor = _monitor(tmp_path, repo)
    file_path = str(tmp_path / "a.txt")

    await monitor._handle_change(
        observed_at=datetime(2026, 7, 16, 10, 0, tzinfo=UTC),
        change_type="created",
        file_path=file_path,
        destination_path=None,
    )

    assert len(repo.recorded) == 1
    assert repo.recorded[0].change_type == "created"
    assert repo.recorded[0].alert_suppressed is False
    monitor.ctx.event_bus.publish.assert_awaited_once()
    payload = monitor.ctx.event_bus.publish.call_args.args[1]
    assert payload["file_path"] == file_path
    assert payload["change_type"] == "created"


@pytest.mark.asyncio
async def test_whitelist_suppresses_alert_but_stores_event(tmp_path: Path) -> None:
    repo = _FakeDirectoryChangesRepository()
    monitor = _monitor(
        tmp_path,
        repo,
        watched_directories=[
            {
                "path": str(tmp_path),
                "whitelist_globs": ["*.log"],
            }
        ],
    )
    file_path = str(tmp_path / "app.log")

    await monitor._handle_change(
        observed_at=datetime(2026, 7, 16, 10, 0, tzinfo=UTC),
        change_type="modified",
        file_path=file_path,
        destination_path=None,
    )

    assert len(repo.recorded) == 1
    assert repo.recorded[0].alert_suppressed is True
    assert repo.recorded[0].suppression_reason == "whitelist"
    monitor.ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_alert_cooldown_suppresses_second_alert(tmp_path: Path) -> None:
    repo = _FakeDirectoryChangesRepository()
    monitor = _monitor(tmp_path, repo, alert_cooldown="00:05:00")
    file_path = str(tmp_path / "bulk.txt")

    first = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
    second = datetime(2026, 7, 16, 10, 1, tzinfo=UTC)
    await monitor._handle_change(
        observed_at=first,
        change_type="modified",
        file_path=file_path,
        destination_path=None,
    )
    await monitor._handle_change(
        observed_at=second,
        change_type="modified",
        file_path=file_path,
        destination_path=None,
    )

    assert len(repo.recorded) == 2
    assert repo.recorded[0].alert_suppressed is False
    assert repo.recorded[1].alert_suppressed is True
    assert repo.recorded[1].suppression_reason == "cooldown"
    assert monitor.ctx.event_bus.publish.await_count == 1


@pytest.mark.asyncio
async def test_renamed_event_uses_destination_path_for_alert(tmp_path: Path) -> None:
    repo = _FakeDirectoryChangesRepository()
    monitor = _monitor(tmp_path, repo)
    src_path = str(tmp_path / "before.txt")
    dst_path = str(tmp_path / "after.txt")

    await monitor._handle_change(
        observed_at=datetime(2026, 7, 16, 10, 0, tzinfo=UTC),
        change_type="renamed",
        file_path=src_path,
        destination_path=dst_path,
    )

    payload = monitor.ctx.event_bus.publish.call_args.args[1]
    assert payload["file_path"] == dst_path
    assert payload["destination_path"] == dst_path
