from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.tools.base import ToolOutcome
from system_sentinel.tools.packages.tool import RequiredPackagesTool
from system_sentinel.tools.update.backends import PackageBackend, UnsupportedDistroError

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
    def __init__(
        self,
        installed: set[str] | None = None,
        install_returncode: int = 0,
        install_stderr: bytes = b"",
        raise_on_install: dict[str, Exception] | None = None,
    ) -> None:
        self._installed: set[str] = installed or set()
        self._install_returncode = install_returncode
        self._install_stderr = install_stderr
        self._raise_on_install: dict[str, Exception] = raise_on_install or {}
        self.install_calls: list[str] = []

    async def upgrade(self, *, dry_run: bool = False) -> tuple[bytes, bytes, int]:
        return b"", b"", 0

    async def reboot_required(self) -> bool:
        return False

    def parse_upgraded_packages(self, stdout: bytes) -> list[str]:
        return []

    async def is_installed(self, package: str) -> bool:
        return package in self._installed

    async def install(self, package: str) -> tuple[bytes, bytes, int]:
        self.install_calls.append(package)
        if package in self._raise_on_install:
            raise self._raise_on_install[package]
        if self._install_returncode == 0:
            self._installed.add(package)
        return b"", self._install_stderr, self._install_returncode


def _make_tool(
    required: list[str] | None = None,
    config: dict[str, Any] | None = None,
    backend: PackageBackend | None = None,
) -> RequiredPackagesTool:
    cfg: dict[str, Any] = {
        "enabled": True,
        "schedule": "0 */6 * * *",
        "required": required or [],
    }
    if config:
        cfg.update(config)
    return RequiredPackagesTool(cfg, _make_ctx(), backend=backend or FakeBackend())


# ---------------------------------------------------------------------------
# AC: required_packages list configured in config.yaml
# ---------------------------------------------------------------------------


def test_schedule_returns_configured_value() -> None:
    tool = _make_tool(config={"schedule": "0 */6 * * *"})
    assert tool.schedule() == "0 */6 * * *"


def test_empty_required_list_succeeds_immediately() -> None:
    tool = _make_tool(required=[])
    # synchronous — no packages to check means no work
    assert tool.is_enabled() is True


# ---------------------------------------------------------------------------
# AC: all packages present — no installs triggered
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_present_returns_success_with_no_installs() -> None:
    backend = FakeBackend(installed={"curl", "ufw", "fail2ban"})
    tool = _make_tool(required=["curl", "ufw", "fail2ban"], backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert backend.install_calls == []
    assert result.details["missing"] == []


# ---------------------------------------------------------------------------
# AC: missing package is auto-installed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_package_is_installed() -> None:
    backend = FakeBackend(installed={"curl"})
    tool = _make_tool(required=["curl", "ufw"], backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert "ufw" in backend.install_calls
    assert "ufw" in result.details["installed"]


# ---------------------------------------------------------------------------
# AC: chat notification sent when missing package detected and reinstalled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_package_publishes_detected_and_installed_events() -> None:
    backend = FakeBackend(installed=set())
    tool = _make_tool(required=["curl"], backend=backend)

    await tool.run()

    event_types = [c[0][0] for c in tool.ctx.event_bus.publish.call_args_list]
    assert any("detected" in e for e in event_types)
    assert any("installed" in e for e in event_types)


# ---------------------------------------------------------------------------
# AC: install failure → warning notification + recorded in audit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_install_failure_publishes_warning_event() -> None:
    backend = FakeBackend(installed=set(), install_returncode=1, install_stderr=b"E: broken")
    tool = _make_tool(required=["curl"], backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    event_types = [c[0][0] for c in tool.ctx.event_bus.publish.call_args_list]
    assert any("failed" in e for e in event_types)
    assert "curl" in result.details.get("failed", [])


@pytest.mark.asyncio
async def test_install_exception_does_not_raise() -> None:
    backend = FakeBackend(
        installed=set(),
        raise_on_install={"curl": OSError("permission denied")},
    )
    tool = _make_tool(required=["curl"], backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    assert result.error is not None or "curl" in result.details.get("failed", [])


# ---------------------------------------------------------------------------
# AC: successful auto-installs recorded in audit log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_successful_install_appended_to_audit_log() -> None:
    backend = FakeBackend(installed=set())
    tool = _make_tool(required=["curl"], backend=backend)

    await tool.run()

    tool.ctx.audit.append.assert_awaited()
    call_str = str(tool.ctx.audit.append.call_args_list)
    assert "curl" in call_str


# ---------------------------------------------------------------------------
# AC: partial failure — some installed, some not
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_failure_outcome_is_failure() -> None:
    backend = FakeBackend(
        installed={"curl"},
        install_returncode=1,
    )
    tool = _make_tool(required=["curl", "ufw", "fail2ban"], backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    assert "ufw" in result.details.get("failed", [])
    assert "fail2ban" in result.details.get("failed", [])


# ---------------------------------------------------------------------------
# AC: unsupported distro handled gracefully
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unsupported_distro_returns_failure() -> None:
    from unittest.mock import patch

    tool = RequiredPackagesTool(
        {"enabled": True, "required": ["curl"]},
        _make_ctx(),
        backend=None,
    )

    with patch(
        "system_sentinel.tools.packages.tool.detect_backend",
        side_effect=UnsupportedDistroError("gentoo"),
    ):
        result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    assert result.error is not None


# ---------------------------------------------------------------------------
# AC: empty required list still records a success audit entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_required_list_records_audit() -> None:
    tool = _make_tool(required=[])

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    tool.ctx.audit.append.assert_awaited_once()
