from __future__ import annotations

from datetime import UTC, datetime
import logging
from unittest.mock import AsyncMock

import pytest

from system_sentinel.chat.access_control import ChatAccessControl, UserRole
from system_sentinel.chat.base import InboundMessage


def _msg(user_id: str, text: str = "!status") -> InboundMessage:
    return InboundMessage(
        adapter="discord",
        channel_id="123",
        user_id=user_id,
        username=f"user-{user_id}",
        text=text,
        raw={},
        received_at=datetime.now(UTC),
    )


def _access(config: dict) -> ChatAccessControl:
    return ChatAccessControl(config, logging.getLogger("test"), enabled_adapters={"discord"})


def test_string_allowed_user_gets_admin_role() -> None:
    access = _access(
        {"chat_adapters": {"discord": {"allowed_users": ["1001"]}}},
    )
    decision = access.authorize(_msg("1001", "!update"), ["!update"])
    assert decision.authorized is True
    assert decision.role is UserRole.ADMIN


def test_readonly_user_can_run_readonly_command() -> None:
    access = _access(
        {"chat_adapters": {"discord": {"allowed_users": [{"id": "2002", "role": "readonly"}]}}},
    )
    decision = access.authorize(_msg("2002", "!status"), ["!status"])
    assert decision.authorized is True
    assert decision.role is UserRole.READONLY


def test_readonly_user_can_run_ask_command() -> None:
    access = _access(
        {"chat_adapters": {"discord": {"allowed_users": [{"id": "2002", "role": "readonly"}]}}},
    )
    decision = access.authorize(
        _msg("2002", "!ask why is cpu high"), ["!ask", "why", "is", "cpu", "high"]
    )
    assert decision.authorized is True
    assert decision.role is UserRole.READONLY


def test_readonly_user_can_run_snapshots_typo_alias() -> None:
    access = _access(
        {"chat_adapters": {"discord": {"allowed_users": [{"id": "2002", "role": "readonly"}]}}},
    )
    decision = access.authorize(_msg("2002", "!snaphsots"), ["!snaphsots"])
    assert decision.authorized is True
    assert decision.role is UserRole.READONLY


def test_readonly_user_can_run_audit_command() -> None:
    access = _access(
        {"chat_adapters": {"discord": {"allowed_users": [{"id": "2002", "role": "readonly"}]}}},
    )
    decision = access.authorize(_msg("2002", "!audit"), ["!audit"])
    assert decision.authorized is True
    assert decision.role is UserRole.READONLY


def test_readonly_user_can_run_connections_command() -> None:
    access = _access(
        {"chat_adapters": {"discord": {"allowed_users": [{"id": "2002", "role": "readonly"}]}}},
    )
    decision = access.authorize(_msg("2002", "!connections classify"), ["!connections", "classify"])
    assert decision.authorized is True
    assert decision.role is UserRole.READONLY

    access = _access(
        {
            "chat_adapters": {
                "discord": {
                    "allowed_users": [{"id": "2002", "role": "readonly"}],
                    "unauthorized_response": "deny_message",
                }
            }
        },
    )
    decision = access.authorize(_msg("2002", "!update"), ["!update"])
    assert decision.authorized is False
    assert decision.reason == "readonly_forbidden_command"
    assert decision.respond_with_message is True


def test_missing_allowed_users_refuses_everyone() -> None:
    access = _access({"chat_adapters": {"discord": {}}})
    decision = access.authorize(_msg("9999"), ["!status"])
    assert decision.authorized is False
    assert decision.reason == "user_not_allowed"


@pytest.mark.asyncio
async def test_rejection_is_written_to_audit_log() -> None:
    access = _access({"chat_adapters": {"discord": {"allowed_users": ["1001"]}}})
    audit = AsyncMock()
    message = _msg("7777", "!cleanup now")

    decision = access.authorize(message, ["!cleanup", "now"])
    assert decision.authorized is False

    await access.audit_rejection(audit, message, ["!cleanup", "now"], decision.reason)

    audit.append.assert_awaited_once()
    kwargs = audit.append.call_args.kwargs
    assert kwargs["action_type"] == "chat_command"
    assert kwargs["source"] == "chat:discord:7777"
    assert kwargs["details"]["command"] == "!cleanup"
