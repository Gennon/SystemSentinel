from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from system_sentinel.core.self_update import SelfUpdateError, SelfUpdateMonitor

if TYPE_CHECKING:
    from pathlib import Path


class _FakeProc:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


def _proc(stdout: str = "", stderr: str = "", returncode: int = 0) -> _FakeProc:
    return _FakeProc(stdout=stdout.encode(), stderr=stderr.encode(), returncode=returncode)


def _monitor_config(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "self_update": {
            "enabled": True,
            "repository_path": str(tmp_path),
            "remote": "origin",
            "branch": "main",
            "reinstall": False,
            "check_interval_seconds": 30,
        }
    }
    cfg["self_update"].update(overrides)
    return cfg


@pytest.mark.asyncio
async def test_check_and_apply_update_returns_false_when_heads_match(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_exec(*args: str, **kwargs: Any) -> _FakeProc:
        calls.append(args)
        if "fetch" in args:
            return _proc()
        if args[-2:] == ("rev-parse", "HEAD"):
            return _proc(stdout="abc")
        return _proc(stdout="abc")

    monitor = SelfUpdateMonitor(_monitor_config(tmp_path), MagicMock())
    with patch(
        "system_sentinel.core.self_update.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        updated = await monitor.check_and_apply_update()

    assert updated is False
    assert not any("pull" in call for call in calls)


@pytest.mark.asyncio
async def test_check_and_apply_update_pulls_when_remote_is_newer(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_exec(*args: str, **kwargs: Any) -> _FakeProc:
        calls.append(args)
        if "fetch" in args:
            return _proc()
        if args[-2:] == ("rev-parse", "HEAD"):
            return _proc(stdout="abc")
        if args[-2:] == ("rev-parse", "origin/main"):
            return _proc(stdout="def")
        if "pull" in args:
            return _proc()
        raise AssertionError(f"Unexpected command: {args}")

    monitor = SelfUpdateMonitor(_monitor_config(tmp_path), MagicMock())
    with patch(
        "system_sentinel.core.self_update.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        updated = await monitor.check_and_apply_update()

    assert updated is True
    assert any("pull" in call for call in calls)


@pytest.mark.asyncio
async def test_check_and_apply_update_raises_on_fetch_failure(tmp_path: Path) -> None:
    async def fake_exec(*args: str, **kwargs: Any) -> _FakeProc:
        if "fetch" in args:
            return _proc(stderr="network error", returncode=1)
        raise AssertionError(f"Unexpected command: {args}")

    monitor = SelfUpdateMonitor(_monitor_config(tmp_path), MagicMock())
    with (
        patch(
            "system_sentinel.core.self_update.asyncio.create_subprocess_exec",
            side_effect=fake_exec,
        ),
        pytest.raises(SelfUpdateError, match="git fetch failed"),
    ):
        await monitor.check_and_apply_update()


@pytest.mark.asyncio
async def test_dubious_ownership_is_auto_fixed_and_fetch_retried(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []
    fetch_calls = 0

    async def fake_exec(*args: str, **kwargs: Any) -> _FakeProc:
        nonlocal fetch_calls
        calls.append(args)
        if "fetch" in args:
            fetch_calls += 1
            if fetch_calls == 1:
                return _proc(stderr="fatal: detected dubious ownership in repository", returncode=1)
            return _proc()
        if args[:3] == ("git", "config", "--global"):
            return _proc()
        if args[-2:] == ("rev-parse", "HEAD"):
            return _proc(stdout="abc")
        if args[-2:] == ("rev-parse", "origin/main"):
            return _proc(stdout="abc")
        raise AssertionError(f"Unexpected command: {args}")

    monitor = SelfUpdateMonitor(_monitor_config(tmp_path), MagicMock())
    with patch(
        "system_sentinel.core.self_update.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        updated = await monitor.check_and_apply_update()

    assert updated is False
    assert fetch_calls == 2
    assert any(call[:3] == ("git", "config", "--global") for call in calls)


def test_disabled_self_update_does_not_enable_monitor(tmp_path: Path) -> None:
    monitor = SelfUpdateMonitor(
        {"self_update": {"enabled": False, "repository_path": str(tmp_path)}},
        MagicMock(),
    )
    assert monitor.enabled is False
