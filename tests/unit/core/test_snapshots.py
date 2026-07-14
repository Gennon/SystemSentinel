from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.snapshots import (
    SnapshotError,
    SnapshotManager,
    SnapshotRecord,
    _error_text,
    _run_command,
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


class _FakeProc:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return b"ok", b""


@pytest.mark.asyncio
async def test_run_command_uses_noninteractive_sudo_for_non_root() -> None:
    called: list[tuple[str, ...]] = []

    async def fake_exec(*args: str, **kwargs: object) -> _FakeProc:
        called.append(args)
        return _FakeProc()

    with (
        patch("system_sentinel.core.snapshots.os.geteuid", return_value=1000),
        patch("system_sentinel.core.snapshots.shutil.which", return_value="/usr/bin/sudo"),
        patch(
            "system_sentinel.core.snapshots.asyncio.create_subprocess_exec",
            side_effect=fake_exec,
        ),
    ):
        await _run_command("snapper", "list")

    assert called[0][:3] == ("/usr/bin/sudo", "-n", "snapper")


@pytest.mark.asyncio
async def test_run_command_raises_when_sudo_missing_for_non_root() -> None:
    with (
        patch("system_sentinel.core.snapshots.os.geteuid", return_value=1000),
        patch("system_sentinel.core.snapshots.shutil.which", return_value=None),
        pytest.raises(SnapshotError, match="sudo"),
    ):
        await _run_command("snapper", "list")


def test_error_text_includes_sudoers_hint_for_sudo_denials() -> None:
    message = _error_text(
        type(
            "_R",
            (),
            {
                "stdout": b"",
                "stderr": b"sudo: a password is required",
                "returncode": 1,
            },
        )()
    )
    assert "NOPASSWD sudo" in message
