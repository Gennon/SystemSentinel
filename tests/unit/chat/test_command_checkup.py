"""Tests for US-045: AI full system check (!checkup command)."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.chat.base import InboundMessage
from system_sentinel.chat.command_checkup import (
    build_checkup_prompt,
    gather_checkup_context,
    handle_checkup_command,
    perform_checkup,
)
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.db.audit_repository import SqliteAuditRepository
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.file_integrity_repository import FileIntegrityRepository
from system_sentinel.db.login_repository import LoginRepository
from system_sentinel.db.vulnerability_repository import VulnerabilityRepository
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
def repos(db: DatabaseConnection):
    """Return a dict of the four repos used by gather_checkup_context."""
    return {
        "vuln_repo": VulnerabilityRepository(db),
        "login_repo": LoginRepository(db),
        "integrity_repo": FileIntegrityRepository(db),
        "audit_repo": SqliteAuditRepository(db),
    }


def _message(text: str = "!checkup") -> InboundMessage:
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

    async def complete(self, *, prompt, system_prompt=None, model=None, timeout_seconds=None):
        return LLMResponse(
            text=(
                "1. [INFO] CPU at 12%, all good.\n"
                "2. [WARNING] No vulnerability scan data available — run vulnscan.\n"
                "3. [INFO] File integrity: no mismatches."
            ),
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=200,
            completion_tokens=50,
        )


class _FailingLLMClient(_FakeLLMClient):
    async def complete(self, **kwargs):
        raise LLMUnavailableError("provider offline")


# ---------------------------------------------------------------------------
# gather_checkup_context
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gather_checkup_context_returns_resources(repos) -> None:
    fake_psutil = type(
        "P",
        (),
        {
            "cpu_percent": staticmethod(lambda interval=None: 25.0),
            "virtual_memory": staticmethod(lambda: type("M", (), {"percent": 55.0})()),
            "disk_usage": staticmethod(lambda path: type("D", (), {"percent": 70.0})()),
        },
    )()

    with patch("system_sentinel.chat.command_checkup.psutil", fake_psutil):
        ctx = await gather_checkup_context(**repos)

    assert ctx["resources"]["cpu_percent"] == 25.0
    assert ctx["resources"]["ram_percent"] == 55.0
    assert ctx["resources"]["disk_percent"] == 70.0


@pytest.mark.asyncio
async def test_gather_checkup_context_no_vulnscan_when_empty(repos) -> None:
    ctx = await gather_checkup_context(**repos)
    assert "vulnscan" not in ctx


@pytest.mark.asyncio
async def test_gather_checkup_context_includes_vulnscan(db: DatabaseConnection, repos) -> None:
    await db.connection.execute(
        """
        INSERT INTO vulnerability_scans
            (scanned_at, score, warning_count, suggestion_count, top_findings_json, report_text)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(UTC).isoformat(),
            "65",
            3,
            7,
            json.dumps(["AUTH-9328", "CRYP-7931"]),
            "full report text",
        ),
    )
    await db.connection.commit()

    ctx = await gather_checkup_context(**repos)
    assert "vulnscan" in ctx
    assert ctx["vulnscan"]["warning_count"] == 3
    assert "AUTH-9328" in ctx["vulnscan"]["top_findings"]


@pytest.mark.asyncio
async def test_gather_checkup_context_no_hardening_when_empty(repos) -> None:
    ctx = await gather_checkup_context(**repos)
    assert "hardening" not in ctx


@pytest.mark.asyncio
async def test_gather_checkup_context_includes_recent_alerts(db: DatabaseConnection, repos) -> None:
    await db.connection.execute(
        """
        INSERT INTO audit_log (timestamp, action_type, source, description, outcome, details_json)
        VALUES (datetime('now'), 'alert_fired', 'monitor', 'CPU high', 'success', ?)
        """,
        (json.dumps({"severity": "warning"}),),
    )
    await db.connection.commit()

    ctx = await gather_checkup_context(**repos)
    assert len(ctx["recent_alerts"]) == 1
    assert ctx["recent_alerts"][0]["severity"] == "warning"


@pytest.mark.asyncio
async def test_gather_checkup_context_uses_login_repo(db: DatabaseConnection, repos) -> None:
    """Login anomalies are fetched via LoginRepository.anomalies_since()."""
    await db.connection.execute(
        """
        INSERT INTO login_anomalies
            (observed_at, anomaly_type, username, ip_address, details_json)
        VALUES (datetime('now'), 'brute_force', 'root', '1.2.3.4', '{}')
        """
    )
    await db.connection.commit()

    ctx = await gather_checkup_context(**repos)
    assert len(ctx["login_anomalies"]) == 1
    assert ctx["login_anomalies"][0]["type"] == "brute_force"
    assert ctx["login_anomalies"][0]["ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_gather_checkup_context_uses_integrity_repo(db: DatabaseConnection, repos) -> None:
    """File integrity mismatches are fetched via FileIntegrityRepository.recent_mismatches()."""
    await db.connection.execute(
        """
        INSERT INTO file_integrity_baselines
            (path, source_path, expected_sha256, created_at, updated_at,
             last_verified_at, last_status)
        VALUES (?, ?, ?, datetime('now'), datetime('now'), datetime('now'), 'mismatch')
        """,
        ("/etc/passwd", "/etc/passwd", "abc123"),
    )
    await db.connection.commit()

    ctx = await gather_checkup_context(**repos)
    assert len(ctx["integrity_mismatches"]) == 1
    assert ctx["integrity_mismatches"][0]["file_path"] == "/etc/passwd"


# ---------------------------------------------------------------------------
# build_checkup_prompt
# ---------------------------------------------------------------------------


def test_build_checkup_prompt_includes_sections() -> None:
    context = {
        "resources": {"cpu_percent": 30.0, "ram_percent": 60.0, "disk_percent": 45.0},
        "vulnscan": {
            "scanned_at": "2024-01-01T00:00:00",
            "score": "70",
            "warning_count": 2,
            "suggestion_count": 5,
            "top_findings": ["FINDING-1"],
        },
        "hardening": {
            "timestamp": "2024-01-01T00:00:00",
            "outcome": "success",
            "total_checks": 10,
            "failed_checks": [{"id": "SSH-001", "title": "SSH root login", "remediated": False}],
        },
        "login_anomalies": [],
        "recent_alerts": [],
        "service_health": [],
        "integrity_mismatches": [],
    }
    prompt = build_checkup_prompt(context)

    assert "=== RESOURCE USAGE ===" in prompt
    assert "CPU: 30.0%" in prompt
    assert "=== VULNERABILITY SCAN ===" in prompt
    assert "Score: 70" in prompt
    assert "FINDING-1" in prompt
    assert "=== HARDENING AUDIT ===" in prompt
    assert "FAIL: SSH root login" in prompt
    assert "=== LOGIN ANOMALIES (last 7 days) ===" in prompt
    assert "None detected." in prompt
    assert "=== FILE INTEGRITY ===" in prompt
    assert "[CRITICAL], [WARNING], or [INFO]" in prompt


def test_build_checkup_prompt_no_data() -> None:
    prompt = build_checkup_prompt({})
    assert "=== VULNERABILITY SCAN ===" in prompt
    assert "No vulnerability scan data available." in prompt
    assert "No hardening audit data available." in prompt


# ---------------------------------------------------------------------------
# perform_checkup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_perform_checkup_returns_report(db: DatabaseConnection) -> None:
    audit = AsyncMock()
    report = await perform_checkup(
        db=db,
        llm_client=_FakeLLMClient(),  # type: ignore[arg-type]
        audit=audit,
        source="test",
    )

    assert "[INFO]" in report or "[WARNING]" in report
    audit.append.assert_awaited_once()
    call_kwargs = audit.append.call_args.kwargs
    assert call_kwargs["action_type"] == "system_checkup"
    assert call_kwargs["outcome"] == "success"


@pytest.mark.asyncio
async def test_perform_checkup_no_audit_no_error(db: DatabaseConnection) -> None:
    report = await perform_checkup(db=db, llm_client=_FakeLLMClient())  # type: ignore[arg-type]
    assert report  # non-empty


@pytest.mark.asyncio
async def test_perform_checkup_propagates_llm_error(db: DatabaseConnection) -> None:
    with pytest.raises(LLMUnavailableError):
        await perform_checkup(db=db, llm_client=_FailingLLMClient())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# handle_checkup_command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_checkup_command_returns_report(db: DatabaseConnection) -> None:
    response = await handle_checkup_command(
        message=_message(),
        db=db,
        llm_client=_FakeLLMClient(),  # type: ignore[arg-type]
    )
    assert response is not None
    assert "Full System Check" in response.text
    assert "[INFO]" in response.text or "[WARNING]" in response.text


@pytest.mark.asyncio
async def test_handle_checkup_command_no_llm(db: DatabaseConnection) -> None:
    response = await handle_checkup_command(
        message=_message(),
        db=db,
        llm_client=None,
    )
    assert response is not None
    assert "not configured" in response.text.lower()


@pytest.mark.asyncio
async def test_handle_checkup_command_llm_unavailable(db: DatabaseConnection) -> None:
    response = await handle_checkup_command(
        message=_message(),
        db=db,
        llm_client=_FailingLLMClient(),  # type: ignore[arg-type]
    )
    assert response is not None
    assert "unavailable" in response.text.lower()


@pytest.mark.asyncio
async def test_handle_checkup_command_truncates_long_report(db: DatabaseConnection) -> None:
    class _LongReportLLM(_FakeLLMClient):
        async def complete(self, **kwargs):
            return LLMResponse(
                text="x" * 5000,
                model_used="llama3.2",
                provider="ollama",
                prompt_tokens=100,
                completion_tokens=200,
            )

    response = await handle_checkup_command(
        message=_message(),
        db=db,
        llm_client=_LongReportLLM(),  # type: ignore[arg-type]
    )
    assert len(response.text) <= 3100  # 3000 + header text
