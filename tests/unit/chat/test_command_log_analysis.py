"""Tests for US-047: AI log analysis for sentinel improvements (!analyze-logs)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from system_sentinel.chat.base import InboundMessage
from system_sentinel.chat.command_log_analysis import (
    build_log_analysis_prompt,
    gather_log_analysis_context,
    handle_log_analysis_command,
    perform_log_analysis,
    redact_sensitive_content,
)
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.db.audit_repository import SqliteAuditRepository
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.llm.base import LLMResponse

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path):
    conn = DatabaseConnection(tmp_path / "test.db")
    await conn.connect()
    yield conn
    await conn.close()


@pytest.fixture
def audit_repo(db: DatabaseConnection):
    return SqliteAuditRepository(db)


def _message(text: str = "!analyze-logs") -> InboundMessage:
    return InboundMessage(
        adapter="discord",
        channel_id="100",
        user_id="adminuser",
        username="alice",
        text=text,
        raw={},
        received_at=datetime.now(UTC),
    )


class _FakeLLMClient:
    is_enabled = True
    active_provider_name = "ollama"

    async def complete(self, *, prompt, system_prompt=None, model=None, timeout_seconds=None):
        return LLMResponse(
            text="1. [INFO] All tools ran successfully — no action needed.",
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=150,
            completion_tokens=30,
        )


class _FailingLLMClient(_FakeLLMClient):
    async def complete(self, **kwargs):
        raise LLMUnavailableError("provider offline")


# ---------------------------------------------------------------------------
# redact_sensitive_content
# ---------------------------------------------------------------------------


def test_redact_password_equals():
    assert "password=[REDACTED]" in redact_sensitive_content("password=hunter2")


def test_redact_api_key_colon():
    result = redact_sensitive_content("api_key: supersecretvalue")
    assert "supersecretvalue" not in result
    assert "REDACTED" in result


def test_redact_token_quoted():
    result = redact_sensitive_content('token="abc123xyz"')
    assert "abc123xyz" not in result
    assert "REDACTED" in result


def test_redact_aws_key():
    result = redact_sensitive_content("key: AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "REDACTED" in result


def test_redact_pem_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----"
    result = redact_sensitive_content(pem)
    assert "MIIEowIBAAK" not in result
    assert "REDACTED_PRIVATE_KEY" in result


def test_redact_leaves_normal_text_intact():
    text = "CPU usage is 45%. Disk at 70%. No anomalies detected."
    assert redact_sensitive_content(text) == text


# ---------------------------------------------------------------------------
# gather_log_analysis_context
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gather_context_empty_db(audit_repo: SqliteAuditRepository) -> None:
    ctx = await gather_log_analysis_context(audit_repo=audit_repo, look_back_days=7)
    assert ctx["total_entries"] == 0
    assert ctx["failures"] == []
    assert ctx["outcome_counts"] == {}


@pytest.mark.asyncio
async def test_gather_context_counts_outcomes(
    db: DatabaseConnection, audit_repo: SqliteAuditRepository
) -> None:
    await audit_repo.append("tool_run", "scheduler", "Cleanup ran", "success")
    await audit_repo.append("tool_run", "scheduler", "Update failed", "failure")
    await audit_repo.append("alert_fired", "monitor", "CPU high", "success")

    ctx = await gather_log_analysis_context(audit_repo=audit_repo, look_back_days=7)
    assert ctx["total_entries"] == 3
    assert ctx["outcome_counts"]["success"] == 2
    assert ctx["outcome_counts"]["failure"] == 1


@pytest.mark.asyncio
async def test_gather_context_extracts_failures(
    audit_repo: SqliteAuditRepository,
) -> None:
    await audit_repo.append("tool_run", "scheduler", "Update failed: connection refused", "failure")
    await audit_repo.append("tool_run", "scheduler", "Cleanup OK", "success")

    ctx = await gather_log_analysis_context(audit_repo=audit_repo, look_back_days=7)
    assert len(ctx["failures"]) == 1
    assert ctx["failures"][0]["action_type"] == "tool_run"
    assert ctx["failures"][0]["outcome"] == "failure"
    assert "connection refused" in ctx["failures"][0]["description"]


@pytest.mark.asyncio
async def test_gather_context_redacts_in_failures(
    audit_repo: SqliteAuditRepository,
) -> None:
    await audit_repo.append("tool_run", "scheduler", "Update failed: password=topsecret", "failure")

    ctx = await gather_log_analysis_context(audit_repo=audit_repo, look_back_days=7)
    assert len(ctx["failures"]) == 1
    assert "topsecret" not in ctx["failures"][0]["description"]
    assert "REDACTED" in ctx["failures"][0]["description"]


@pytest.mark.asyncio
async def test_gather_context_action_type_counts(
    audit_repo: SqliteAuditRepository,
) -> None:
    await audit_repo.append("tool_run", "scheduler", "desc", "success")
    await audit_repo.append("tool_run", "scheduler", "desc", "success")
    await audit_repo.append("alert_fired", "monitor", "desc", "success")

    ctx = await gather_log_analysis_context(audit_repo=audit_repo, look_back_days=7)
    assert ctx["action_type_counts"]["tool_run"] == 2
    assert ctx["action_type_counts"]["alert_fired"] == 1


# ---------------------------------------------------------------------------
# build_log_analysis_prompt
# ---------------------------------------------------------------------------


def test_build_prompt_contains_section_headers():
    ctx = {
        "look_back_days": 7,
        "since": "2026-07-22T06:00:00+00:00",
        "total_entries": 5,
        "outcome_counts": {"success": 4, "failure": 1},
        "action_type_counts": {"tool_run": 3, "alert_fired": 2},
        "failure_action_types": {"tool_run": 1},
        "failures": [
            {
                "timestamp": "2026-07-28T10:00:00",
                "action_type": "tool_run",
                "source": "scheduler",
                "description": "Update failed: timeout",
                "outcome": "failure",
            }
        ],
    }
    prompt = build_log_analysis_prompt(ctx)
    assert "OUTCOME SUMMARY" in prompt
    assert "ACTION TYPE BREAKDOWN" in prompt
    assert "FAILURE / ERROR ENTRIES" in prompt
    assert "success: 4" in prompt
    assert "failure: 1" in prompt
    assert "tool_run: 1 failure(s)" in prompt
    assert "Update failed: timeout" in prompt


def test_build_prompt_no_failures_message():
    ctx = {
        "look_back_days": 3,
        "since": "2026-07-26T00:00:00+00:00",
        "total_entries": 2,
        "outcome_counts": {"success": 2},
        "action_type_counts": {"tool_run": 2},
        "failure_action_types": {},
        "failures": [],
    }
    prompt = build_log_analysis_prompt(ctx)
    assert "No failures or errors recorded" in prompt


# ---------------------------------------------------------------------------
# perform_log_analysis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_perform_log_analysis_returns_report(db: DatabaseConnection) -> None:
    llm = _FakeLLMClient()
    report = await perform_log_analysis(db=db, llm_client=llm, look_back_days=7)
    assert "INFO" in report


@pytest.mark.asyncio
async def test_perform_log_analysis_writes_audit_entry(db: DatabaseConnection) -> None:
    llm = _FakeLLMClient()
    audit_mock = AsyncMock()

    await perform_log_analysis(
        db=db,
        llm_client=llm,
        audit=audit_mock,
        look_back_days=7,
        source="chat:discord:alice",
    )

    audit_mock.append.assert_awaited_once()
    call_kwargs = audit_mock.append.call_args.kwargs
    assert call_kwargs["action_type"] == "log_analysis"
    assert call_kwargs["outcome"] == "success"
    assert call_kwargs["source"] == "chat:discord:alice"


# ---------------------------------------------------------------------------
# handle_log_analysis_command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_command_no_llm(db: DatabaseConnection) -> None:
    response = await handle_log_analysis_command(
        message=_message(),
        db=db,
        llm_client=None,
    )
    assert "not configured" in response.text


@pytest.mark.asyncio
async def test_handle_command_llm_unavailable(db: DatabaseConnection) -> None:
    response = await handle_log_analysis_command(
        message=_message(),
        db=db,
        llm_client=_FailingLLMClient(),
    )
    assert "unavailable" in response.text


@pytest.mark.asyncio
async def test_handle_command_success(db: DatabaseConnection) -> None:
    response = await handle_log_analysis_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient(),
        look_back_days=7,
    )
    assert "Log Analysis" in response.text
    assert "INFO" in response.text


@pytest.mark.asyncio
async def test_handle_command_includes_look_back_days(db: DatabaseConnection) -> None:
    response = await handle_log_analysis_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient(),
        look_back_days=14,
    )
    assert "14d" in response.text
