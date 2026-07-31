"""Tests for AlertCorrelationService (US-048)."""

from __future__ import annotations

import asyncio
import contextlib
import logging

import pytest

from system_sentinel.alerts.correlation import AlertCorrelationService
from system_sentinel.alerts.handler import AlertHandler
from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.chat.router import ChatRouter
from system_sentinel.core.event_bus import InProcessEventBus
from system_sentinel.llm.base import LLMResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_router() -> tuple[ChatRouter, list[OutboundMessage]]:
    router = ChatRouter()
    calls: list[OutboundMessage] = []

    class _Rec:
        name = "rec"
        logger = logging.getLogger("test.rec")

        async def send_to_default(self, message: OutboundMessage) -> None:
            calls.append(message)

        async def start(self) -> None: ...
        async def stop(self) -> None: ...
        async def send(self, channel_id: str, message: OutboundMessage) -> None: ...

    router.register(_Rec())  # type: ignore[arg-type]
    return router, calls


class _FakeLLM:
    def __init__(self, response_text: str = "NOT_CORRELATED") -> None:
        self.is_enabled = True
        self.response_text = response_text
        self.calls: list[str] = []

    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        command_type: str | None = None,
        severity: str | None = None,
    ) -> LLMResponse:
        _ = command_type, severity
        self.calls.append(prompt)
        return LLMResponse(text=self.response_text, model_used="test-model", provider="test")

    async def list_models(self) -> list[str]:
        return ["test-model"]

    async def health_check(self) -> bool:
        return True


class _DisabledLLM(_FakeLLM):
    def __init__(self) -> None:
        super().__init__()
        self.is_enabled = False


class _FakeAudit:
    def __init__(self) -> None:
        self.records: list[dict] = []

    async def append(self, **kwargs: object) -> None:
        self.records.append(dict(kwargs))


_MSG_CPU = OutboundMessage(
    title="CPU threshold exceeded",
    text="CPU is at 95%",
    severity=AlertSeverity.CRITICAL,
)

_MSG_RAM = OutboundMessage(
    title="RAM threshold exceeded",
    text="RAM is at 92%",
    severity=AlertSeverity.CRITICAL,
)

_MSG_DISK = OutboundMessage(
    title="Disk threshold exceeded",
    text="Disk is at 91%",
    severity=AlertSeverity.WARNING,
)


# ---------------------------------------------------------------------------
# Unit tests: _parse_llm_response
# ---------------------------------------------------------------------------


def _make_svc(llm: object = None) -> AlertCorrelationService:
    router, _ = _make_router()
    return AlertCorrelationService(
        router=router,
        audit=None,
        llm=llm,
        logger=logging.getLogger("test"),
        enabled=True,
        window_seconds=0.01,
        timeout_seconds=5.0,
    )


def _fake_batch(svc: AlertCorrelationService) -> list:
    from system_sentinel.alerts.correlation import _PendingAlert

    return [
        _PendingAlert(event_type="alert.cpu.threshold_exceeded", payload={}, message=_MSG_CPU),
        _PendingAlert(event_type="alert.ram.threshold_exceeded", payload={}, message=_MSG_RAM),
    ]


def test_parse_llm_response_correlated_returns_message() -> None:
    svc = _make_svc()
    batch = _fake_batch(svc)
    result = svc._parse_llm_response(
        "CORRELATED: System is under heavy load\nHigh CPU and RAM usage detected simultaneously.",
        batch,
    )
    assert result is not None
    assert "System is under heavy load" in result.title
    assert "alert.cpu.threshold_exceeded" in result.text
    assert "alert.ram.threshold_exceeded" in result.text


def test_parse_llm_response_not_correlated_returns_none() -> None:
    svc = _make_svc()
    batch = _fake_batch(svc)
    result = svc._parse_llm_response("NOT_CORRELATED", batch)
    assert result is None


def test_parse_llm_response_uses_highest_severity() -> None:
    svc = _make_svc()
    batch = _fake_batch(svc)
    result = svc._parse_llm_response("CORRELATED: Under load", batch)
    assert result is not None
    assert result.severity == AlertSeverity.CRITICAL


def test_parse_llm_response_highest_severity_with_mixed_levels() -> None:
    from system_sentinel.alerts.correlation import _PendingAlert

    svc = _make_svc()
    batch = [
        _PendingAlert(event_type="a", payload={}, message=_MSG_DISK),  # WARNING
        _PendingAlert(event_type="b", payload={}, message=_MSG_RAM),  # CRITICAL
    ]
    result = svc._parse_llm_response("CORRELATED: Something", batch)
    assert result is not None
    assert result.severity == AlertSeverity.CRITICAL


def test_parse_llm_response_includes_explanation() -> None:
    svc = _make_svc()
    batch = _fake_batch(svc)
    result = svc._parse_llm_response(
        "CORRELATED: High load\nThe system is running out of compute resources.", batch
    )
    assert result is not None
    assert "compute resources" in result.text


# ---------------------------------------------------------------------------
# Integration: flush behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_flush_single_alert_broadcasts_directly() -> None:
    router, calls = _make_router()
    audit = _FakeAudit()
    svc = AlertCorrelationService(
        router=router,
        audit=audit,
        llm=None,
        logger=logging.getLogger("test"),
        enabled=True,
        window_seconds=0.01,
        timeout_seconds=5.0,
    )
    await svc.submit("alert.cpu.threshold_exceeded", {}, _MSG_CPU)
    await asyncio.sleep(0.05)

    assert len(calls) == 1
    assert calls[0] is _MSG_CPU
    assert audit.records[0]["outcome"] == "not_correlated"
    assert audit.records[0]["details"]["reason"] == "single_alert"


@pytest.mark.asyncio
async def test_flush_multiple_alerts_llm_unavailable_sends_individually() -> None:
    router, calls = _make_router()
    audit = _FakeAudit()
    svc = AlertCorrelationService(
        router=router,
        audit=audit,
        llm=_DisabledLLM(),
        logger=logging.getLogger("test"),
        enabled=True,
        window_seconds=0.01,
        timeout_seconds=5.0,
    )
    await svc.submit("alert.cpu.threshold_exceeded", {}, _MSG_CPU)
    await svc.submit("alert.ram.threshold_exceeded", {}, _MSG_RAM)
    await asyncio.sleep(0.05)

    assert len(calls) == 2
    assert audit.records[0]["details"]["reason"] == "llm_unavailable"


@pytest.mark.asyncio
async def test_flush_multiple_alerts_llm_correlates_sends_single_message() -> None:
    router, calls = _make_router()
    audit = _FakeAudit()
    llm = _FakeLLM("CORRELATED: System under heavy load\nCPU and RAM spiked together.")
    svc = AlertCorrelationService(
        router=router,
        audit=audit,
        llm=llm,
        logger=logging.getLogger("test"),
        enabled=True,
        window_seconds=0.01,
        timeout_seconds=5.0,
    )
    await svc.submit("alert.cpu.threshold_exceeded", {}, _MSG_CPU)
    await svc.submit("alert.ram.threshold_exceeded", {}, _MSG_RAM)
    await asyncio.sleep(0.05)

    assert len(calls) == 1
    assert "Correlated alert" in calls[0].title
    assert "System under heavy load" in calls[0].title
    assert audit.records[0]["outcome"] == "correlated"
    assert audit.records[0]["details"]["alert_count"] == 2


@pytest.mark.asyncio
async def test_flush_multiple_alerts_llm_not_correlated_sends_individually() -> None:
    router, calls = _make_router()
    audit = _FakeAudit()
    llm = _FakeLLM("NOT_CORRELATED")
    svc = AlertCorrelationService(
        router=router,
        audit=audit,
        llm=llm,
        logger=logging.getLogger("test"),
        enabled=True,
        window_seconds=0.01,
        timeout_seconds=5.0,
    )
    await svc.submit("alert.cpu.threshold_exceeded", {}, _MSG_CPU)
    await svc.submit("alert.ram.threshold_exceeded", {}, _MSG_RAM)
    await asyncio.sleep(0.05)

    assert len(calls) == 2
    assert audit.records[0]["outcome"] == "not_correlated"
    assert audit.records[0]["details"]["reason"] == "no_common_root_cause"


@pytest.mark.asyncio
async def test_flush_llm_error_falls_back_to_individual_sends() -> None:
    router, calls = _make_router()
    audit = _FakeAudit()

    class _ErrorLLM(_FakeLLM):
        async def complete(self, **kwargs: object) -> LLMResponse:  # type: ignore[override]
            raise RuntimeError("connection refused")

    svc = AlertCorrelationService(
        router=router,
        audit=audit,
        llm=_ErrorLLM(),
        logger=logging.getLogger("test"),
        enabled=True,
        window_seconds=0.01,
        timeout_seconds=5.0,
    )
    await svc.submit("alert.cpu.threshold_exceeded", {}, _MSG_CPU)
    await svc.submit("alert.ram.threshold_exceeded", {}, _MSG_RAM)
    await asyncio.sleep(0.05)

    assert len(calls) == 2
    assert "llm_error" in audit.records[0]["details"]["reason"]


@pytest.mark.asyncio
async def test_audit_records_event_types() -> None:
    router, _ = _make_router()
    audit = _FakeAudit()
    llm = _FakeLLM("NOT_CORRELATED")
    svc = AlertCorrelationService(
        router=router,
        audit=audit,
        llm=llm,
        logger=logging.getLogger("test"),
        enabled=True,
        window_seconds=0.01,
        timeout_seconds=5.0,
    )
    await svc.submit("alert.cpu.threshold_exceeded", {}, _MSG_CPU)
    await svc.submit("alert.disk.threshold_exceeded", {}, _MSG_DISK)
    await asyncio.sleep(0.05)

    event_types = audit.records[0]["details"]["event_types"]
    assert "alert.cpu.threshold_exceeded" in event_types
    assert "alert.disk.threshold_exceeded" in event_types


# ---------------------------------------------------------------------------
# AlertHandler integration: correlation config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handler_with_correlation_disabled_sends_immediately() -> None:
    """When correlation is disabled, alerts broadcast normally without buffering."""
    router, calls = _make_router()
    handler = AlertHandler(
        router,
        config={"llm": {"alert_correlation": {"enabled": False}}},
    )
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish(
        "alert.cpu.threshold_exceeded",
        {"current_value": 95.0, "threshold": ">90%"},
    )

    assert len(calls) == 1
    assert "CPU" in (calls[0].title or "")


@pytest.mark.asyncio
async def test_handler_with_correlation_enabled_buffers_alerts() -> None:
    """When correlation is enabled, alerts are not broadcast immediately."""
    router, calls = _make_router()
    handler = AlertHandler(
        router,
        config={"llm": {"alert_correlation": {"enabled": True, "window": "00:00:10"}}},
    )
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish(
        "alert.cpu.threshold_exceeded",
        {"current_value": 95.0, "threshold": ">90%"},
    )

    # Alert is buffered — not yet broadcast
    assert len(calls) == 0

    # Cancel the pending flush task to avoid teardown warnings
    if handler._correlation._flush_task and not handler._correlation._flush_task.done():
        handler._correlation._flush_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await handler._correlation._flush_task


@pytest.mark.asyncio
async def test_handler_correlation_config_reads_window_hhmmss() -> None:
    """window config key is parsed as HH:MM:SS."""
    router, _ = _make_router()
    handler = AlertHandler(
        router,
        config={"llm": {"alert_correlation": {"enabled": True, "window": "00:02:30"}}},
    )
    assert handler._correlation._window_seconds == 150.0


@pytest.mark.asyncio
async def test_handler_correlation_disabled_by_default() -> None:
    router, _ = _make_router()
    handler = AlertHandler(router)
    assert not handler._correlation.enabled
