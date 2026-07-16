from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.tools.base import ToolOutcome
from system_sentinel.tools.hardening.tool import CommandResult, HardeningTool


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


class FakeHardeningBackend:
    def __init__(
        self,
        *,
        files: dict[str, str] | None = None,
        sysctl_values: dict[str, str] | None = None,
        enabled_services: set[str] | None = None,
    ) -> None:
        self.files = files or {}
        self.sysctl_values = sysctl_values or {}
        self.enabled_services = enabled_services or set()
        self.writes: dict[str, str] = {}
        self.commands: list[list[str]] = []

    def read_text(self, path: Path) -> str | None:
        return self.files.get(str(path))

    def write_text(self, path: Path, content: str) -> None:
        self.writes[str(path)] = content
        self.files[str(path)] = content

    def list_matching(self, pattern: str) -> list[Path]:
        prefix = pattern.split("*", 1)[0]
        matches = [Path(path) for path in self.files if path.startswith(prefix)]
        return sorted(matches)

    def run(self, args: list[str]) -> CommandResult:
        self.commands.append(args)
        if args[:2] == ["sysctl", "-n"]:
            key = args[2]
            value = self.sysctl_values.get(key)
            if value is None:
                return CommandResult(returncode=1, stdout="", stderr="missing")
            return CommandResult(returncode=0, stdout=f"{value}\n", stderr="")
        if args == ["sysctl", "--system"]:
            return CommandResult(returncode=0, stdout="applied", stderr="")
        if args[:2] == ["systemctl", "is-enabled"]:
            service = args[2]
            if service in self.enabled_services:
                return CommandResult(returncode=0, stdout="enabled\n", stderr="")
            return CommandResult(returncode=1, stdout="disabled\n", stderr="")
        if args[:3] == ["systemctl", "disable", "--now"]:
            service = args[3]
            self.enabled_services.discard(service)
            return CommandResult(returncode=0, stdout="", stderr="")
        if args[:2] == ["systemctl", "reload"]:
            return CommandResult(returncode=0, stdout="", stderr="")
        return CommandResult(returncode=0, stdout="", stderr="")


def _tool(
    config: dict[str, Any] | None = None,
    backend: FakeHardeningBackend | None = None,
) -> HardeningTool:
    cfg = {"enabled": True}
    if config:
        cfg.update(config)
    return HardeningTool(cfg, _make_ctx(), backend=backend or FakeHardeningBackend())


def test_default_schedule_is_weekly() -> None:
    tool = _tool()
    assert tool.schedule() == "7d 00:00:00"


def test_invalid_schedule_falls_back_to_default() -> None:
    tool = _tool({"schedule": "0 3 * * 1"})
    assert tool.schedule() == "7d 00:00:00"


def test_run_on_startup_defaults_true() -> None:
    tool = _tool()
    assert tool.config["run_on_startup"] is True


@pytest.mark.asyncio
async def test_hardening_audit_passes_when_all_checks_match() -> None:
    backend = FakeHardeningBackend(
        files={
            "/etc/ssh/sshd_config": "PermitRootLogin no\nPasswordAuthentication no\n",
            "/etc/security/pwquality.conf": "minlen = 14\nminclass = 3\n",
        },
        sysctl_values={
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.default.accept_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.default.send_redirects": "0",
            "net.ipv4.tcp_syncookies": "1",
            "kernel.randomize_va_space": "2",
        },
        enabled_services=set(),
    )
    tool = _tool(backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert "remediated 0" in result.summary.lower()


@pytest.mark.asyncio
async def test_hardening_audit_fails_without_auto_remediation() -> None:
    backend = FakeHardeningBackend(
        files={
            "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n",
            "/etc/security/pwquality.conf": "minlen = 8\nminclass = 1\n",
        },
        sysctl_values={
            "net.ipv4.conf.all.accept_redirects": "1",
            "net.ipv4.conf.default.accept_redirects": "1",
            "net.ipv4.conf.all.send_redirects": "1",
            "net.ipv4.conf.default.send_redirects": "1",
            "net.ipv4.tcp_syncookies": "0",
            "kernel.randomize_va_space": "0",
        },
        enabled_services={"telnet.socket"},
    )
    tool = _tool({"auto_remediate": False}, backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.FAILURE
    assert result.details["failed_checks"]


@pytest.mark.asyncio
async def test_hardening_auto_remediation_applies_and_notifies_per_item() -> None:
    backend = FakeHardeningBackend(
        files={
            "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n",
            "/etc/security/pwquality.conf": "minlen = 8\nminclass = 1\n",
        },
        sysctl_values={
            "net.ipv4.conf.all.accept_redirects": "1",
            "net.ipv4.conf.default.accept_redirects": "1",
            "net.ipv4.conf.all.send_redirects": "1",
            "net.ipv4.conf.default.send_redirects": "1",
            "net.ipv4.tcp_syncookies": "0",
            "kernel.randomize_va_space": "0",
        },
        enabled_services={"telnet.socket"},
    )
    tool = _tool({"auto_remediate": True}, backend=backend)

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    remediated = result.details["remediated_checks"]
    assert len(remediated) == 5
    assert tool.ctx.event_bus.publish.await_count == 5
    assert "/etc/ssh/sshd_config.d/99-system-sentinel-hardening.conf" in backend.writes
