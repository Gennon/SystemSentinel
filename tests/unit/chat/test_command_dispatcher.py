from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from system_sentinel.chat.base import InboundMessage, InboundReaction
from system_sentinel.chat.command_dispatcher import ChatCommandDispatcher
from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult

if TYPE_CHECKING:
    from pathlib import Path


class _FakeScheduler:
    pass


class _FakeMonitorRegistry:
    @property
    def monitors(self) -> list[object]:
        return []


class _FakeTool(BaseTool):
    name = "security_update"
    display_name = "Security Update"
    description = "fake"

    async def run(self) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary="Security update completed.",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )


async def _dispatcher(
    tmp_path: Path, config: dict, tools: dict[str, BaseTool]
) -> ChatCommandDispatcher:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    dispatcher = ChatCommandDispatcher(
        config=config,
        app_ctx=ctx,
        scheduler=_FakeScheduler(),  # type: ignore[arg-type]
        tools=tools,
        monitor_registry=_FakeMonitorRegistry(),  # type: ignore[arg-type]
        db=db,
    )
    return dispatcher


def _message(text: str = "!help", channel_id: str = "100") -> InboundMessage:
    return InboundMessage(
        adapter="discord",
        channel_id=channel_id,
        user_id="123",
        username="alice",
        text=text,
        raw={},
        received_at=datetime.now(UTC),
    )


def _reaction(channel_id: str = "100") -> InboundReaction:
    return InboundReaction(
        adapter="discord",
        channel_id=channel_id,
        user_id="123",
        username="alice",
        emoji="✅",
        raw={},
        received_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_help_command_returns_supported_commands(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {
            "chat_adapters": {
                "discord": {"channel_id": "100", "command_prefix": "!"},
            }
        },
        {},
    )

    response = await dispatcher.handle_message(_message("!help"), ["!help"])
    assert response is not None
    assert "!status" in response.text
    assert "!cleanup" in response.text


@pytest.mark.asyncio
async def test_message_ignored_outside_command_channel(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}},
        {},
    )

    response = await dispatcher.handle_message(_message("!status", channel_id="200"), ["!status"])
    assert response is None


@pytest.mark.asyncio
async def test_update_requires_confirmation_and_runs_on_reaction(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    tool = _FakeTool({}, ctx)
    dispatcher = ChatCommandDispatcher(
        config={"chat_adapters": {"discord": {"channel_id": "100"}}},
        app_ctx=ctx,
        scheduler=_FakeScheduler(),  # type: ignore[arg-type]
        tools={"security_update": tool},
        monitor_registry=_FakeMonitorRegistry(),  # type: ignore[arg-type]
        db=db,
    )

    confirmation = await dispatcher.handle_message(_message("!update"), ["!update"])
    assert confirmation is not None
    assert "Confirm !update" in confirmation.text

    response = await dispatcher.handle_reaction(_reaction())
    assert response is not None
    assert "Security update completed." in response.text


@pytest.mark.asyncio
async def test_custom_prefix_is_honored(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100", "command_prefix": "/"}}},
        {},
    )

    response = await dispatcher.handle_message(_message("/help"), ["/help"])
    assert response is not None
    assert "Available commands:" in response.text


@pytest.mark.asyncio
async def test_storage_command_handles_permission_denied_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected_path = "/home/username"
    dispatcher = await _dispatcher(
        tmp_path,
        {
            "chat_adapters": {"discord": {"channel_id": "100"}},
            "tools": {"storage": {"paths": [protected_path]}},
        },
        {},
    )

    monkeypatch.setattr(
        "system_sentinel.chat.command_dispatcher.os.path.exists",
        lambda path: str(path) == protected_path,
    )

    def _raise_permission_denied(_path: str) -> None:
        raise PermissionError("[Errno 13] Permission denied")

    monkeypatch.setattr(
        "system_sentinel.chat.command_dispatcher.psutil.disk_usage",
        _raise_permission_denied,
    )

    response = await dispatcher.handle_message(_message("!storage"), ["!storage"])
    assert response is not None
    assert f"{protected_path}: permission denied" in response.text


@pytest.mark.asyncio
async def test_connections_classify_returns_latest_classifications(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    repo = ConnectionRepository(db)
    now = datetime.now(UTC)
    await repo.record_classification(
        ip_address="8.8.8.8",
        category="likely_access_attempt",
        confidence=0.91,
        recommended_action="block",
        reasons=["high_attempt_volume", "sensitive_port_targeted"],
        attempts=9,
        distinct_ports=3,
        recurrence_count=5,
        sensitive_port_targeted=True,
        reverse_dns=None,
        asn_organization=None,
        geoip_country=None,
        protocol="tcp",
        observed_at=now,
    )
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    dispatcher = ChatCommandDispatcher(
        config={"chat_adapters": {"discord": {"channel_id": "100"}}},
        app_ctx=ctx,
        scheduler=_FakeScheduler(),  # type: ignore[arg-type]
        tools={},
        monitor_registry=_FakeMonitorRegistry(),  # type: ignore[arg-type]
        db=db,
    )

    response = await dispatcher.handle_message(
        _message("!connections classify"), ["!connections", "classify"]
    )
    assert response is not None
    assert "8.8.8.8" in response.text
    assert "likely_access_attempt" in response.text
    assert "block" in response.text
