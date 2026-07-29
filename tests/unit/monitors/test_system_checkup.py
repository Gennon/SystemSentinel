"""Tests for US-045: SystemCheckupMonitor (scheduled full system check)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from unittest.mock import AsyncMock, patch

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.llm.base import LLMResponse
from system_sentinel.monitors.system_checkup import (
    _DEFAULT_INTERVAL_SECONDS,
    _LAST_SENT_KEY,
    SystemCheckupMonitor,
)


@pytest.fixture
async def db(tmp_path):
    conn = DatabaseConnection(tmp_path / "test.db")
    await conn.connect()
    yield conn
    await conn.close()


class _FakeLLMClient:
    is_enabled = True
    active_provider_name = "ollama"

    async def complete(self, *, prompt, system_prompt=None, model=None, timeout_seconds=None):
        return LLMResponse(
            text="1. [INFO] System healthy.",
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=100,
            completion_tokens=20,
        )


def _make_ctx(llm=None) -> AppContext:
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=AsyncMock(),
        event_bus=event_bus,
        logger=logging.getLogger("test"),
        llm=llm,
    )


@pytest.mark.asyncio
async def test_collect_publishes_checkup_event(db: DatabaseConnection) -> None:
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 40.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 30.0})()
        await monitor.collect()

    ctx.event_bus.publish.assert_awaited_once()
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.system.checkup"
    assert "report" in payload
    assert "[INFO]" in payload["report"]
    assert "provider" in payload


@pytest.mark.asyncio
async def test_collect_skips_when_llm_disabled(db: DatabaseConnection) -> None:
    class _DisabledLLM(_FakeLLMClient):
        is_enabled = False

    ctx = _make_ctx(llm=_DisabledLLM())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_skips_when_no_llm(db: DatabaseConnection) -> None:
    ctx = _make_ctx(llm=None)
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_skips_when_no_db() -> None:
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=None)

    await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_does_not_raise_on_llm_error(db: DatabaseConnection) -> None:
    from system_sentinel.core.exceptions import LLMUnavailableError

    class _FailingLLM(_FakeLLMClient):
        async def complete(self, **kwargs):
            raise LLMUnavailableError("offline")

    ctx = _make_ctx(llm=_FailingLLM())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 40.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 30.0})()
        # Must not raise
        await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_writes_to_audit(db: DatabaseConnection) -> None:
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 5.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 20.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 15.0})()
        await monitor.collect()

    ctx.audit.append.assert_awaited_once()
    call_kwargs = ctx.audit.append.call_args.kwargs
    assert call_kwargs["action_type"] == "system_checkup"
    assert call_kwargs["outcome"] == "success"


@pytest.mark.asyncio
async def test_collect_skips_when_within_interval(db: DatabaseConnection) -> None:
    """collect() should be a no-op when called again before the interval elapses."""
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 40.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 30.0})()
        await monitor.collect()
        await monitor.collect()  # second call within interval

    ctx.event_bus.publish.assert_awaited_once()  # only once


@pytest.mark.asyncio
async def test_collect_runs_again_after_interval_elapsed(db: DatabaseConnection) -> None:
    """collect() should run again once the configured interval has passed."""
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    past = (datetime.now(UTC) - timedelta(seconds=_DEFAULT_INTERVAL_SECONDS + 1)).isoformat()
    from system_sentinel.db.connection_repository import ConnectionRepository
    repo = ConnectionRepository(db)
    await repo.set_state(_LAST_SENT_KEY, past)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 40.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 30.0})()
        await monitor.collect()

    ctx.event_bus.publish.assert_awaited_once()


@pytest.mark.asyncio
async def test_collect_respects_custom_interval(db: DatabaseConnection) -> None:
    """interval config key should override the default."""
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={"interval": "0d 00:30:00"}, app_ctx=ctx, db=db)
    assert monitor._interval_seconds() == 30 * 60


def test_timeout_seconds_defaults_to_60() -> None:
    ctx = _make_ctx()
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx)
    assert monitor._timeout_seconds() == 60.0


def test_timeout_seconds_reads_from_config() -> None:
    ctx = _make_ctx()
    monitor = SystemCheckupMonitor(config={"timeout_seconds": 120}, app_ctx=ctx)
    assert monitor._timeout_seconds() == 120.0


@pytest.fixture
async def db(tmp_path):
    conn = DatabaseConnection(tmp_path / "test.db")
    await conn.connect()
    yield conn
    await conn.close()


class _FakeLLMClient:
    is_enabled = True
    active_provider_name = "ollama"

    async def complete(self, *, prompt, system_prompt=None, model=None, timeout_seconds=None):
        return LLMResponse(
            text="1. [INFO] System healthy.",
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=100,
            completion_tokens=20,
        )


def _make_ctx(llm=None) -> AppContext:
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=AsyncMock(),
        event_bus=event_bus,
        logger=logging.getLogger("test"),
        llm=llm,
    )


@pytest.mark.asyncio
async def test_collect_publishes_checkup_event(db: DatabaseConnection) -> None:
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 40.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 30.0})()
        await monitor.collect()

    ctx.event_bus.publish.assert_awaited_once()
    event_type, payload = ctx.event_bus.publish.call_args.args
    assert event_type == "alert.system.checkup"
    assert "report" in payload
    assert "[INFO]" in payload["report"]
    assert "provider" in payload


@pytest.mark.asyncio
async def test_collect_skips_when_llm_disabled(db: DatabaseConnection) -> None:
    class _DisabledLLM(_FakeLLMClient):
        is_enabled = False

    ctx = _make_ctx(llm=_DisabledLLM())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_skips_when_no_llm(db: DatabaseConnection) -> None:
    ctx = _make_ctx(llm=None)
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_skips_when_no_db() -> None:
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=None)

    await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_does_not_raise_on_llm_error(db: DatabaseConnection) -> None:
    from system_sentinel.core.exceptions import LLMUnavailableError

    class _FailingLLM(_FakeLLMClient):
        async def complete(self, **kwargs):
            raise LLMUnavailableError("offline")

    ctx = _make_ctx(llm=_FailingLLM())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 40.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 30.0})()
        # Must not raise
        await monitor.collect()

    ctx.event_bus.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_collect_writes_to_audit(db: DatabaseConnection) -> None:
    ctx = _make_ctx(llm=_FakeLLMClient())
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx, db=db)

    with patch("system_sentinel.chat.command_checkup.psutil") as mock_psutil:
        mock_psutil.cpu_percent.return_value = 5.0
        mock_psutil.virtual_memory.return_value = type("M", (), {"percent": 20.0})()
        mock_psutil.disk_usage.return_value = type("D", (), {"percent": 15.0})()
        await monitor.collect()

    ctx.audit.append.assert_awaited_once()
    call_kwargs = ctx.audit.append.call_args.kwargs
    assert call_kwargs["action_type"] == "system_checkup"
    assert call_kwargs["outcome"] == "success"


def test_timeout_seconds_defaults_to_60() -> None:
    ctx = _make_ctx()
    monitor = SystemCheckupMonitor(config={}, app_ctx=ctx)
    assert monitor._timeout_seconds() == 60.0


def test_timeout_seconds_reads_from_config() -> None:
    ctx = _make_ctx()
    monitor = SystemCheckupMonitor(config={"timeout_seconds": 120}, app_ctx=ctx)
    assert monitor._timeout_seconds() == 120.0
