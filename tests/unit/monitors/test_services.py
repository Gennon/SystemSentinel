from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.monitors.services import ServiceMonitor, _CommandResult


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


def _command_runner(script: list[tuple[tuple[str, ...], tuple[int, str, str]]]):
    queue = list(script)

    async def _run(argv: list[str]):
        if not queue:
            raise AssertionError(f"Unexpected command with no scripted result: {argv!r}")
        expected_argv, result = queue.pop(0)
        assert tuple(argv) == expected_argv
        return _CommandResult(*result)

    return _run


@pytest.mark.asyncio
async def test_collect_skips_when_no_critical_services_configured() -> None:
    ctx = _make_ctx()
    monitor = ServiceMonitor({"enabled": True, "critical_services": []}, ctx)

    await monitor.collect()

    ctx.event_bus.publish.assert_not_called()
    ctx.audit.append.assert_not_called()


@pytest.mark.asyncio
async def test_collect_publishes_detection_and_success_follow_up() -> None:
    ctx = _make_ctx()
    monitor = ServiceMonitor(
        {
            "enabled": True,
            "critical_services": ["nginx.service"],
            "check_interval": "00:00:00",
            "max_restart_attempts": 3,
            "journal_lines": 5,
        },
        ctx,
        command_runner=_command_runner(
            [
                (("/bin/systemctl", "is-active", "nginx.service"), (3, "inactive\n", "")),
                (
                    (
                        "/usr/bin/journalctl",
                        "-u",
                        "nginx.service",
                        "-n",
                        "5",
                        "--no-pager",
                        "--output=short",
                    ),
                    (0, "line 1\nline 2\n", ""),
                ),
                (("sudo", "/bin/systemctl", "restart", "nginx.service"), (0, "", "")),
                (("/bin/systemctl", "is-active", "nginx.service"), (0, "active\n", "")),
            ]
        ),
    )

    await monitor.collect()

    assert ctx.event_bus.publish.await_count == 2
    first_event_type, first_payload = ctx.event_bus.publish.await_args_list[0].args
    second_event_type, second_payload = ctx.event_bus.publish.await_args_list[1].args
    assert first_event_type == "alert.service.failure_detected"
    assert first_payload["service_name"] == "nginx.service"
    assert first_payload["status"] == "inactive"
    assert "line 1" in first_payload["last_journal_lines"]
    assert second_event_type == "alert.service.restart_result"
    assert second_payload["service_name"] == "nginx.service"
    assert second_payload["succeeded"] is True
    ctx.audit.append.assert_awaited_once()
    assert ctx.audit.append.await_args.kwargs["outcome"] == "success"


@pytest.mark.asyncio
async def test_collect_emits_exhausted_after_retry_limit_then_stops_retrying() -> None:
    ctx = _make_ctx()
    command_script: list[tuple[tuple[str, ...], tuple[int, str, str]]] = [
        (("/bin/systemctl", "is-active", "redis.service"), (3, "failed\n", "")),
        (
            (
                "/usr/bin/journalctl",
                "-u",
                "redis.service",
                "-n",
                "20",
                "--no-pager",
                "--output=short",
            ),
            (0, "boom\n", ""),
        ),
        (("sudo", "/bin/systemctl", "restart", "redis.service"), (1, "", "permission denied")),
        (("/bin/systemctl", "is-active", "redis.service"), (3, "failed\n", "")),
        (("/bin/systemctl", "is-active", "redis.service"), (3, "failed\n", "")),
        (
            (
                "/usr/bin/journalctl",
                "-u",
                "redis.service",
                "-n",
                "20",
                "--no-pager",
                "--output=short",
            ),
            (0, "boom\n", ""),
        ),
        (("sudo", "/bin/systemctl", "restart", "redis.service"), (1, "", "permission denied")),
        (("/bin/systemctl", "is-active", "redis.service"), (3, "failed\n", "")),
        (("/bin/systemctl", "is-active", "redis.service"), (3, "failed\n", "")),
    ]

    monitor = ServiceMonitor(
        {
            "enabled": True,
            "critical_services": ["redis.service"],
            "check_interval": "00:00:00",
            "max_restart_attempts": 2,
        },
        ctx,
        command_runner=_command_runner(command_script),
    )

    await monitor.collect()
    await monitor.collect()
    await monitor.collect()

    published_events = [call.args[0] for call in ctx.event_bus.publish.await_args_list]
    assert published_events.count("alert.service.failure_detected") == 2
    assert published_events.count("alert.service.restart_result") == 2
    assert published_events.count("alert.service.restart_exhausted") == 1
    assert ctx.audit.append.await_count == 2


@pytest.mark.asyncio
async def test_collect_respects_check_interval() -> None:
    ctx = _make_ctx()
    command_calls: list[tuple[str, ...]] = []

    async def runner(argv: list[str]) -> Any:
        command_calls.append(tuple(argv))
        return _CommandResult(0, "active\n", "")

    monitor = ServiceMonitor(
        {
            "enabled": True,
            "critical_services": ["sshd.service"],
            "check_interval": "00:01:00",
        },
        ctx,
        command_runner=runner,
    )

    await monitor.collect()
    await monitor.collect()

    assert command_calls == [("/bin/systemctl", "is-active", "sshd.service")]
