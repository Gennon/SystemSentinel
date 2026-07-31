"""Tests for the !explain command (US-051)."""

from __future__ import annotations

from datetime import UTC, datetime
import json
import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from system_sentinel.chat.base import InboundMessage
from system_sentinel.chat.command_explain import handle_explain_command
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.llm.base import LLMResponse

if TYPE_CHECKING:
    from pathlib import Path


class _FakeLLMClient:
    is_enabled = True
    active_provider_name = "ollama"

    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMResponse:
        _ = system_prompt, model, timeout_seconds
        self.last_prompt = prompt
        return LLMResponse(
            text="High CPU was caused by a runaway process. Kill it with `kill <pid>`.",
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=50,
            completion_tokens=20,
        )


class _DisabledLLMClient:
    is_enabled = False
    active_provider_name: str | None = None


class _FailingLLMClient:
    is_enabled = True
    active_provider_name = "ollama"

    async def complete(self, **kwargs: Any) -> LLMResponse:
        raise LLMUnavailableError("provider offline")


def _message(text: str = "!explain") -> InboundMessage:
    return InboundMessage(
        adapter="discord",
        channel_id="100",
        user_id="user1",
        username="alice",
        text=text,
        raw={},
        received_at=datetime.now(UTC),
    )


async def _db_with_alerts(tmp_path: Path, count: int = 1) -> DatabaseConnection:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    for i in range(count):
        details = json.dumps({"severity": "warning", "chat_notification_suppressed": False})
        await db.connection.execute(
            """
            INSERT INTO audit_log (timestamp, action_type, source, description, outcome, details_json)
            VALUES (?, 'alert_fired', ?, ?, 'success', ?)
            """,
            (
                datetime(2024, 1, 1, 12, i, 0, tzinfo=UTC).isoformat(),
                "alert.cpu.threshold_exceeded",
                f"CPU threshold exceeded (sample {i})",
                details,
            ),
        )
    await db.connection.commit()
    return db


@pytest.mark.asyncio
async def test_explain_no_llm_returns_config_hint(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    response = await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=None,
        audit=AsyncMock(),
    )
    assert "not configured" in response.text.lower()


@pytest.mark.asyncio
async def test_explain_disabled_llm_returns_config_hint(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    response = await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=_DisabledLLMClient(),
        audit=AsyncMock(),
    )
    assert "not configured" in response.text.lower()


@pytest.mark.asyncio
async def test_explain_no_alerts_returns_friendly_message(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    response = await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient(),
        audit=AsyncMock(),
    )
    assert "no recent alerts" in response.text.lower()


@pytest.mark.asyncio
async def test_explain_returns_ai_explanation(tmp_path: Path) -> None:
    db = await _db_with_alerts(tmp_path, count=1)
    llm = _FakeLLMClient()
    response = await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=llm,
        audit=AsyncMock(),
    )
    assert "AI Explanation" in response.text
    assert "runaway process" in response.text


@pytest.mark.asyncio
async def test_explain_includes_recent_alert_history_in_prompt(tmp_path: Path) -> None:
    db = await _db_with_alerts(tmp_path, count=5)
    llm = _FakeLLMClient()
    await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=llm,
        audit=AsyncMock(),
    )
    assert hasattr(llm, "last_prompt")
    assert "Recent Alert History" in llm.last_prompt


@pytest.mark.asyncio
async def test_explain_includes_user_context_in_prompt(tmp_path: Path) -> None:
    db = await _db_with_alerts(tmp_path, count=1)
    llm = _FakeLLMClient()
    await handle_explain_command(
        message=_message("!explain why is memory climbing"),
        db=db,
        llm_client=llm,
        audit=AsyncMock(),
    )
    assert "why is memory climbing" in llm.last_prompt


@pytest.mark.asyncio
async def test_explain_records_success_in_audit(tmp_path: Path) -> None:
    db = await _db_with_alerts(tmp_path, count=1)
    audit = AsyncMock()
    await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient(),
        audit=audit,
    )
    audit.append.assert_awaited_once()
    call_kwargs = audit.append.call_args.kwargs
    assert call_kwargs["action_type"] == "explain_alert"
    assert call_kwargs["outcome"] == "success"


@pytest.mark.asyncio
async def test_explain_llm_unavailable_returns_error(tmp_path: Path) -> None:
    db = await _db_with_alerts(tmp_path, count=1)
    response = await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=_FailingLLMClient(),
        audit=AsyncMock(),
    )
    assert "unavailable" in response.text.lower()


@pytest.mark.asyncio
async def test_explain_includes_current_system_state_in_prompt(tmp_path: Path) -> None:
    db = await _db_with_alerts(tmp_path, count=1)
    llm = _FakeLLMClient()
    await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=llm,
        audit=AsyncMock(),
    )
    assert "Current System State" in llm.last_prompt


@pytest.mark.asyncio
async def test_explain_suppressed_alert_shows_note_in_prompt(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    details = json.dumps({"severity": "warning", "chat_notification_suppressed": True})
    await db.connection.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'alert_fired', 'alert.cpu.threshold_exceeded', 'CPU threshold exceeded', 'success', ?)
        """,
        (datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC).isoformat(), details),
    )
    await db.connection.commit()
    llm = _FakeLLMClient()
    await handle_explain_command(
        message=_message(),
        db=db,
        llm_client=llm,
        audit=AsyncMock(),
    )
    assert "suppressed" in llm.last_prompt


@pytest.mark.asyncio
async def test_explain_command_via_dispatcher(tmp_path: Path) -> None:
    """Integration-style: verify !explain is wired into the dispatcher."""
    from unittest.mock import AsyncMock

    from system_sentinel.chat.command_dispatcher import ChatCommandDispatcher
    from system_sentinel.core.context import AppContext

    db = await _db_with_alerts(tmp_path, count=1)
    llm = _FakeLLMClient()
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
        llm=llm,
    )

    class _FakeScheduler:
        pass

    class _FakeMonitorRegistry:
        @property
        def monitors(self) -> list[object]:
            return []

    dispatcher = ChatCommandDispatcher(
        config={"chat_adapters": {"discord": {"channel_id": "100"}}},
        app_ctx=ctx,
        scheduler=_FakeScheduler(),  # type: ignore[arg-type]
        tools={},
        monitor_registry=_FakeMonitorRegistry(),  # type: ignore[arg-type]
        db=db,
    )

    msg = _message("!explain")
    response = await dispatcher.handle_message(msg, ["!explain"])
    assert response is not None
    assert "AI Explanation" in response.text or "runaway" in response.text
