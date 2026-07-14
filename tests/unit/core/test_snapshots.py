from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.snapshots import (
    SnapshotManager,
    SnapshotRecord,
)


class _FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def create(self, label: str) -> SnapshotRecord:
        return SnapshotRecord(
            backend=self.name,
            snapshot_id="new-id",
            created_at="2026-07-14T00:00:00+00:00",
            label=label,
        )

    async def list_recent(self, *, limit: int) -> list[SnapshotRecord]:
        return [
            SnapshotRecord(self.name, "new-id", "2026-07-14T00:00:00+00:00", "latest"),
            SnapshotRecord(self.name, "old-1", "2026-07-13T00:00:00+00:00", "old-1"),
            SnapshotRecord(self.name, "old-2", "2026-07-12T00:00:00+00:00", "old-2"),
        ][:limit]

    async def delete(self, snapshot_id: str) -> None:
        self.deleted.append(snapshot_id)


def _manager(*, keep_last: int = 1) -> tuple[SnapshotManager, AsyncMock, _FakeBackend]:
    audit = AsyncMock()
    backend = _FakeBackend()
    manager = SnapshotManager(
        backend=backend,
        keep_last=keep_last,
        audit=audit,
        logger=logging.getLogger("test"),
    )
    return manager, audit, backend


@pytest.mark.asyncio
async def test_create_snapshot_records_create_and_deletes_excess() -> None:
    manager, audit, backend = _manager(keep_last=1)
    await manager.create_snapshot("pre-update origin/main")

    assert backend.deleted == ["old-1", "old-2"]
    assert audit.append.await_count == 3
    actions = [kwargs["action_type"] for _, kwargs in audit.append.await_args_list]
    assert actions == ["snapshot_create", "snapshot_delete", "snapshot_delete"]


def test_from_config_disables_when_no_backend_available(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    audit = AsyncMock()
    with patch("system_sentinel.core.snapshots.shutil.which", return_value=None):
        manager = SnapshotManager.from_config(
            self_update_cfg={"snapshots": {"backend": "auto"}},
            audit=audit,
            logger=logging.getLogger("test"),
        )
    assert manager.enabled is False
    assert "no supported tool is available" in caplog.text.lower()


def test_from_config_invalid_keep_last_uses_default() -> None:
    audit = AsyncMock()
    manager = SnapshotManager.from_config(
        self_update_cfg={"snapshots": {"backend": "none", "keep_last": "invalid-number"}},
        audit=audit,
        logger=logging.getLogger("test"),
    )
    assert manager.enabled is False
