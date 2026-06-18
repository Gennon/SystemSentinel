from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.tools.base import ToolOutcome
from system_sentinel.tools.update.backends import PackageBackend, UnsupportedDistroError
from system_sentinel.tools.update.tool import SecurityUpdateTool

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_ctx() -> AppContext:
    audit = AsyncMock()
    audit.append = AsyncMock()
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=audit,
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


class FakeBackend(PackageBackend):
    """Configurable fake backend for tool-level tests."""

    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        reboot: bool = False,
        packages: list[str] | None = None,
        raise_on_upgrade: Exception | None = None,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self._reboot = reboot
        self._packages = packages or []
        self._raise_on_upgrade = raise_on_upgrade
        self.upgrade_calls: list[dict[str, Any]] = []

    async def upgrade(self, *, dry_run: bool = False) -> tuple[bytes, bytes, int]:
        self.upgrade_calls.append({"dry_run": dry_run})
        if self._raise_on_upgrade is not None:
            raise self._raise_on_upgrade
        return self.stdout, self.stderr, self.returncode

    async def reboot_required(self) -> bool:
        return self._reboot

    def parse_upgraded_packages(self, stdout: bytes) -> list[str]:
        return self._packages

    async def is_installed(self, package: str) -> bool:
        return True

    async def install(self, package: str) -> tuple[bytes, bytes, int]:
        return b"", b"", 0


def _make_tool(
    config: dict[str, Any] | None = None,
    backend: PackageBackend | None = None,
) -> SecurityUpdateTool:
    cfg: dict[str, Any] = {
        "enabled": True,
        "schedule": "02:00",
        "dry_run": False,
        "reboot_policy": "notify",
    }
    if config:
        cfg.update(config)
    return SecurityUpdateTool(cfg, _make_ctx(), backend=backend or FakeBackend())


# ---------------------------------------------------------------------------
# AC: schedule can be configured in config.yaml
# ---------------------------------------------------------------------------


def test_schedule_returns_configured_value() -> None:
    tool = _make_tool({"schedule": "03:30"})
    assert tool.schedule() == "03:30"


def test_schedule_defaults_to_none_when_absent() -> None:
    tool = _make_tool({})
    tool.config.pop("schedule", None)
    assert tool.schedule() is None


# ---------------------------------------------------------------------------
# AC: dry-run mode — simulates without applying
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dry_run_returns_skipped_outcome() -> None:
    backend = FakeBackend(stdout=b"5 packages listed")
    tool = _make_tool({"dry_run": True}, backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SKIPPED
    assert "dry" in result.summary.lower() or "simulated" in result.summary.lower()
    assert backend.upgrade_calls[0]["dry_run"] is True


# ---------------------------------------------------------------------------
# AC: only security-classified updates applied (delegated to backend)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_delegates_to_backend_upgrade() -> None:
    backend = FakeBackend(packages=["curl", "ufw"])
    tool = _make_tool(backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert len(backend.upgrade_calls) == 1
    assert backend.upgrade_calls[0]["dry_run"] is False


# ---------------------------------------------------------------------------
# AC: audit log written with timestamp, packages, exit status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_run_appends_to_audit_log() -> None:
    backend = FakeBackend(packages=["curl", "openssh-server"])
    tool = _make_tool(backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    tool.ctx.audit.append.assert_awaited_once()
    call_kwargs = tool.ctx.audit.append.call_args
    assert call_kwargs is not None
    assert "success" in str(call_kwargs).lower()


# ---------------------------------------------------------------------------
# AC: failure → notification via event bus
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failed_update_publishes_failure_event() -> None:
    backend = FakeBackend(
        stderr=b"E: Could not get lock /var/lib/dpkg/lock",
        returncode=1,
    )
    tool = _make_tool(backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    tool.ctx.event_bus.publish.assert_awaited()
    published_event = tool.ctx.event_bus.publish.call_args_list[0][0][0]
    assert "update" in published_event


# ---------------------------------------------------------------------------
# AC: run() never raises — failures expressed in ToolResult
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_never_raises_on_subprocess_exception() -> None:
    backend = FakeBackend(raise_on_upgrade=OSError("No such file"))
    tool = _make_tool(backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    assert result.error is not None


@pytest.mark.asyncio
async def test_run_never_raises_on_unsupported_distro() -> None:
    backend = FakeBackend(
        raise_on_upgrade=UnsupportedDistroError(
            "Arch Linux does not support security-only updates."
        )
    )
    tool = _make_tool(backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    assert result.error is not None


# ---------------------------------------------------------------------------
# AC: reboot flagged via event when required (reboot_policy=notify)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reboot_required_publishes_event_when_policy_is_notify() -> None:
    backend = FakeBackend(packages=["linux-image-generic"], reboot=True)
    tool = _make_tool({"reboot_policy": "notify"}, backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    event_types = [c[0][0] for c in tool.ctx.event_bus.publish.call_args_list]
    assert any("reboot" in e for e in event_types)


# ---------------------------------------------------------------------------
# AC: reboot_policy=never — no reboot event published
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reboot_not_published_when_policy_is_never() -> None:
    backend = FakeBackend(packages=["curl"], reboot=True)
    tool = _make_tool({"reboot_policy": "never"}, backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    event_types = [c[0][0] for c in tool.ctx.event_bus.publish.call_args_list]
    assert not any("reboot" in e for e in event_types)


# ---------------------------------------------------------------------------
# detect_backend() fallback — unsupported distro handled gracefully
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unsupported_distro_at_detection_returns_failure() -> None:
    from unittest.mock import patch

    from system_sentinel.tools.update.backends import UnsupportedDistroError

    tool = SecurityUpdateTool(
        {"enabled": True, "dry_run": False, "reboot_policy": "notify"},
        _make_ctx(),
        backend=None,  # forces detect_backend() call
    )

    with patch(
        "system_sentinel.tools.update.tool.detect_backend",
        side_effect=UnsupportedDistroError("ID=gentoo"),
    ):
        result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    assert result.error is not None
