"""Tests for US-050: AI narrative health reports (!health-story command)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from system_sentinel.chat.base import InboundMessage
from system_sentinel.chat.command_health_story import (
    build_narrative_prompt,
    gather_narrative_context,
    handle_health_story_command,
    perform_health_story,
)
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.db.audit_repository import SqliteAuditRepository
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.metrics_repository import MetricsRepository
from system_sentinel.llm.base import LLMResponse


@pytest.fixture
async def db(tmp_path):
    conn = DatabaseConnection(tmp_path / "test.db")
    await conn.connect()
    yield conn
    await conn.close()


def _message(text: str = "!health-story") -> InboundMessage:
    return InboundMessage(
        adapter="discord",
        channel_id="100",
        user_id="123",
        username="alice",
        text=text,
        raw={},
        received_at=datetime.now(UTC),
    )


class _FakeLLMClient:
    is_enabled = True
    active_provider_name = "ollama"

    async def complete(
        self,
        *,
        prompt,
        system_prompt=None,
        model=None,
        timeout_seconds=None,
        command_type=None,
        severity=None,
    ):
        return LLMResponse(
            text=(
                "System health over the last 7 days has been stable. "
                "CPU usage averaged 25%, RAM at 50%, disk at 70%. "
                "No significant security concerns detected. "
                "All critical services remain operational."
            ),
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=200,
            completion_tokens=100,
        )


class _FailingLLMClient(_FakeLLMClient):
    async def complete(self, **kwargs):
        raise LLMUnavailableError("provider offline")


@pytest.mark.asyncio
async def test_gather_narrative_context_empty_database(db) -> None:
    metrics_repo = MetricsRepository(db)
    audit_repo = SqliteAuditRepository(db)

    ctx = await gather_narrative_context(
        metrics_repo=metrics_repo,
        audit_repo=audit_repo,
        look_back_days=7,
    )

    assert "resource_trends" in ctx
    assert "current_resources" in ctx
    assert "hardening" in ctx
    assert "service_events" in ctx
    assert "notable_alerts" in ctx
    assert ctx["look_back_days"] == 7


@pytest.mark.asyncio
async def test_build_narrative_prompt_formats_context(db) -> None:
    context = {
        "look_back_days": 7,
        "generated_at": "2024-01-01T12:00:00",
        "resource_trends": {
            "cpu": {
                "early_avg": 20.0,
                "late_avg": 25.0,
                "trend": "up 5.0%",
                "sample_count": 100,
            },
            "ram": {
                "early_avg": 40.0,
                "late_avg": 50.0,
                "trend": "up 10.0%",
                "sample_count": 100,
            },
            "disk": {
                "early_avg": 60.0,
                "late_avg": 70.0,
                "trend": "up 10.0%",
                "sample_count": 100,
            },
        },
        "current_resources": {
            "cpu_percent": 25.0,
            "ram_percent": 50.0,
            "disk_percent": 70.0,
        },
        "hardening": None,
        "service_events": [],
        "notable_alerts": [],
    }

    prompt = build_narrative_prompt(context)
    assert "RESOURCE TRENDS" in prompt
    assert "CPU:" in prompt
    assert "up 5.0%" in prompt
    assert "SECURITY POSTURE" in prompt
    assert "NOTABLE EVENTS" in prompt


@pytest.mark.asyncio
async def test_perform_health_story_success(db) -> None:
    llm_client = _FakeLLMClient()
    audit = AsyncMock()

    report = await perform_health_story(
        db=db,
        llm_client=llm_client,
        audit=audit,
        look_back_days=7,
    )

    assert "stable" in report
    assert audit.append.called


@pytest.mark.asyncio
async def test_handle_health_story_command_success(db) -> None:
    llm_client = _FakeLLMClient()
    audit = AsyncMock()
    msg = _message()

    response = await handle_health_story_command(
        message=msg,
        db=db,
        llm_client=llm_client,
        audit=audit,
        look_back_days=7,
    )

    assert response.text is not None
    assert "Health Story" in response.text


@pytest.mark.asyncio
async def test_handle_health_story_command_llm_unavailable(db) -> None:
    msg = _message()

    response = await handle_health_story_command(
        message=msg,
        db=db,
        llm_client=None,
        look_back_days=7,
    )

    assert "LLM assistant is not configured" in response.text


@pytest.mark.asyncio
async def test_handle_health_story_command_llm_fails(db) -> None:
    llm_client = _FailingLLMClient()
    msg = _message()

    response = await handle_health_story_command(
        message=msg,
        db=db,
        llm_client=llm_client,
        look_back_days=7,
    )

    assert "unavailable" in response.text.lower()
