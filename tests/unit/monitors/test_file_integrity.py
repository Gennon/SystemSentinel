from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.monitors.file_integrity import FileIntegrityMonitor

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path


@dataclass
class _RecordedVerification:
    path: str
    status: str
    expected_sha256: str | None
    actual_sha256: str | None


class _FakeFileIntegrityRepository:
    def __init__(self) -> None:
        self.baselines: dict[str, dict[str, str]] = {}
        self.verifications: list[_RecordedVerification] = []
        self.state: dict[str, str] = {}

    async def get_baseline(self, path: str) -> dict[str, str] | None:
        return self.baselines.get(path)

    async def upsert_baseline(
        self,
        *,
        path: str,
        source_path: str,
        expected_sha256: str,
        observed_at: datetime,
    ) -> None:
        _ = source_path, observed_at
        self.baselines[path] = {"expected_sha256": expected_sha256}

    async def record_verification(
        self,
        *,
        path: str,
        checked_at: datetime,
        expected_sha256: str | None,
        actual_sha256: str | None,
        status: str,
        error: str | None = None,
    ) -> None:
        _ = checked_at, error
        self.verifications.append(
            _RecordedVerification(
                path=path,
                status=status,
                expected_sha256=expected_sha256,
                actual_sha256=actual_sha256,
            )
        )

    async def get_state(self, key: str) -> str | None:
        return self.state.get(key)

    async def set_state(self, key: str, value: str) -> None:
        self.state[key] = value


def _make_ctx() -> AppContext:
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=AsyncMock(),
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


@pytest.mark.asyncio
async def test_collect_creates_baseline_on_first_run(tmp_path: Path) -> None:
    target = tmp_path / "critical.conf"
    target.write_text("secure=true\n")
    repo = _FakeFileIntegrityRepository()
    monitor = FileIntegrityMonitor(
        config={
            "enabled": True,
            "verify_interval": "00:00:00",
            "monitored_paths": [str(target)],
        },
        app_ctx=_make_ctx(),
        file_integrity_repo=repo,
    )

    await monitor.collect()

    assert len(repo.verifications) == 1
    assert repo.verifications[0].status == "baseline_created"
    monitor.ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_publishes_alert_on_checksum_mismatch(tmp_path: Path) -> None:
    target = tmp_path / "critical.conf"
    target.write_text("secure=true\n")
    repo = _FakeFileIntegrityRepository()
    monitor = FileIntegrityMonitor(
        config={
            "enabled": True,
            "verify_interval": "00:00:00",
            "monitored_paths": [str(target)],
        },
        app_ctx=_make_ctx(),
        file_integrity_repo=repo,
    )
    await monitor.collect()
    target.write_text("secure=false\n")

    await monitor.collect()

    assert repo.verifications[-1].status == "mismatch"
    monitor.ctx.event_bus.publish.assert_awaited()
    call = monitor.ctx.event_bus.publish.await_args
    assert call.args[0] == "alert.files.integrity_mismatch"
    payload = call.args[1]
    assert payload["file_path"] == str(target.resolve(strict=False))
    assert payload["expected_hash"] != payload["actual_hash"]


@pytest.mark.asyncio
async def test_collect_respects_verify_interval(tmp_path: Path) -> None:
    target = tmp_path / "critical.conf"
    target.write_text("secure=true\n")
    repo = _FakeFileIntegrityRepository()
    monitor = FileIntegrityMonitor(
        config={
            "enabled": True,
            "verify_interval": "00:10:00",
            "monitored_paths": [str(target)],
        },
        app_ctx=_make_ctx(),
        file_integrity_repo=repo,
    )

    await monitor.collect()
    await monitor.collect()

    assert len(repo.verifications) == 1


@pytest.mark.asyncio
async def test_collect_handles_permission_denied_gracefully(tmp_path: Path) -> None:
    target = tmp_path / "protected.conf"
    target.write_text("secret\n")
    target.chmod(0o000)
    repo = _FakeFileIntegrityRepository()
    monitor = FileIntegrityMonitor(
        config={
            "enabled": True,
            "verify_interval": "00:00:00",
            "monitored_paths": [str(target)],
        },
        app_ctx=_make_ctx(),
        file_integrity_repo=repo,
    )

    await monitor.collect()

    assert len(repo.verifications) == 1
    assert repo.verifications[0].status == "permission_denied"
    monitor.ctx.event_bus.publish.assert_not_awaited()
    target.chmod(0o644)
