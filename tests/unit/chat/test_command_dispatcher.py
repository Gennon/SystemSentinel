from __future__ import annotations

from datetime import UTC, datetime
import json
import logging
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from system_sentinel.charts.base import ChartRequest, ChartResult
from system_sentinel.chat.base import InboundMessage, InboundReaction
from system_sentinel.chat.command_dispatcher import ChatCommandDispatcher
from system_sentinel.core.context import AppContext
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.db.connection_repository import ConnectionRepository
from system_sentinel.db.login_repository import LoginRepository
from system_sentinel.llm.base import LLMResponse
from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult
from system_sentinel.tools.firewall.backends import UnsupportedFirewallBackendError

if TYPE_CHECKING:
    from pathlib import Path


class _FakeScheduler:
    pass


class _FakeMonitorRegistry:
    @property
    def monitors(self) -> list[object]:
        return []


class _FakeLLMClient:
    def __init__(self) -> None:
        self.active_provider_name = "ollama"
        self.is_enabled = True
        self.last_prompt: str | None = None

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
            text="Likely high load from package updates.",
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=100,
            completion_tokens=25,
        )

    async def list_models(self) -> list[str]:
        return ["llama3.2"]

    async def health_check(self) -> bool:
        return True


class _FailingLLMClient(_FakeLLMClient):
    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMResponse:
        _ = prompt, system_prompt, model, timeout_seconds
        raise LLMUnavailableError("provider offline")


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


class _FakeFirewallTool(BaseTool):
    name = "firewall"
    display_name = "Firewall"
    description = "fake"

    async def run(self) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary="ok",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )

    async def status_report(self) -> str:
        return "Firewall backend: ufw\nDesired state: MATCH"


class _FailingFirewallTool(BaseTool):
    name = "firewall"
    display_name = "Firewall"
    description = "fake"

    async def run(self) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary="ok",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )

    async def status_report(self) -> str:
        raise UnsupportedFirewallBackendError("No supported firewall backend detected.")


class _FakeImageRenderer:
    name = "image"

    async def render(self, request: ChartRequest) -> ChartResult:
        _ = request
        return ChartResult(
            content_type="image/png",
            payload=b"png-binary",
            filename="cpu-24h.png",
        )


async def _dispatcher(
    tmp_path: Path,
    config: dict,
    tools: dict[str, BaseTool],
    llm: _FakeLLMClient | None = None,
) -> ChatCommandDispatcher:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
        llm=llm,
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
    assert "!snapshots" in response.text
    assert "!audit [--count N]" in response.text
    assert "!ask <question>" in response.text
    assert "!graph <metric> <period>" in response.text


@pytest.mark.asyncio
async def test_graph_command_requires_metric_and_period(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}},
        {},
    )

    response = await dispatcher.handle_message(_message("!graph cpu"), ["!graph", "cpu"])
    assert response is not None
    assert response.text.startswith("Usage: !graph <metric> <period>")


@pytest.mark.asyncio
async def test_graph_command_renders_text_chart(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}, "charts": {"renderer": "text"}},
        {},
    )
    await dispatcher._db.connection.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO system_metrics (timestamp, metric_type, data_json)
        VALUES (?, 'cpu', ?)
        """,
        (datetime.now(UTC).isoformat(), json.dumps({"overall_percent": 44.2})),
    )
    await dispatcher._db.connection.commit()  # type: ignore[attr-defined]

    response = await dispatcher.handle_message(_message("!graph cpu 24h"), ["!graph", "cpu", "24h"])
    assert response is not None
    assert "CPU history (24h)" in response.text
    assert "```text" in response.text


@pytest.mark.asyncio
async def test_graph_command_adds_insufficient_data_note(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}, "charts": {"renderer": "text"}},
        {},
    )
    await dispatcher._db.connection.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO system_metrics (timestamp, metric_type, data_json)
        VALUES (?, 'cpu', ?)
        """,
        (datetime.now(UTC).isoformat(), json.dumps({"overall_percent": 41.0})),
    )
    await dispatcher._db.connection.commit()  # type: ignore[attr-defined]

    response = await dispatcher.handle_message(_message("!graph cpu 7d"), ["!graph", "cpu", "7d"])
    assert response is not None
    assert "Note: insufficient data for full 7d" in response.text


@pytest.mark.asyncio
async def test_graph_command_returns_png_attachment_for_image_renderer(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}},
        {},
    )
    await dispatcher._db.connection.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO system_metrics (timestamp, metric_type, data_json)
        VALUES (?, 'cpu', ?)
        """,
        (datetime.now(UTC).isoformat(), json.dumps({"overall_percent": 66.0})),
    )
    await dispatcher._db.connection.commit()  # type: ignore[attr-defined]
    dispatcher._chart_renderer = _FakeImageRenderer()  # type: ignore[assignment,attr-defined]

    response = await dispatcher.handle_message(_message("!graph cpu 24h"), ["!graph", "cpu", "24h"])
    assert response is not None
    assert response.attachments is not None
    assert len(response.attachments) == 1
    assert response.attachments[0].filename == "cpu-24h.png"


@pytest.mark.asyncio
async def test_ask_command_routes_to_llm(tmp_path: Path) -> None:
    llm = _FakeLLMClient()
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}},
        {},
        llm=llm,
    )

    response = await dispatcher.handle_message(
        _message("!ask why is CPU so high?"),
        ["!ask", "why", "is", "CPU", "so", "high?"],
    )
    assert response is not None
    assert "[ollama:llama3.2]" in response.text
    assert "Likely high load from package updates." in response.text
    assert llm.last_prompt is not None
    assert "Current system context:" in llm.last_prompt


@pytest.mark.asyncio
async def test_ask_command_context_includes_recent_alerts_and_top_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    llm = _FakeLLMClient()
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}},
        {},
        llm=llm,
    )
    await dispatcher._db.connection.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO system_metrics (timestamp, metric_type, data_json)
        VALUES (?, 'cpu', ?)
        """,
        (
            datetime.now(UTC).isoformat(),
            json.dumps(
                {
                    "overall_percent": 92.5,
                    "top_processes": [
                        {"name": "python", "pid": 111, "cpu_percent": 45.0, "ram_bytes": 1_000_000},
                        {
                            "name": "postgres",
                            "pid": 222,
                            "cpu_percent": 22.0,
                            "ram_bytes": 2_000_000,
                        },
                    ],
                }
            ),
        ),
    )
    await dispatcher._db.connection.execute(  # type: ignore[attr-defined]
        """
        INSERT INTO audit_log
            (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'alert_fired', 'alert.cpu.threshold_exceeded', '⚠️ High CPU Usage', 'success', ?)
        """,
        (
            datetime.now(UTC).isoformat(),
            json.dumps({"severity": "warning", "chat_notification_suppressed": False}),
        ),
    )
    await dispatcher._db.connection.commit()  # type: ignore[attr-defined]

    monkeypatch.setattr(
        "system_sentinel.chat.command_dispatcher.psutil.cpu_percent", lambda interval=None: 91.2
    )
    monkeypatch.setattr(
        "system_sentinel.chat.command_dispatcher.psutil.virtual_memory",
        lambda: type("vmem", (), {"percent": 73.3})(),
    )
    monkeypatch.setattr(
        "system_sentinel.chat.command_dispatcher.psutil.disk_usage",
        lambda _path: type("dsk", (), {"percent": 68.4})(),
    )

    response = await dispatcher.handle_message(
        _message("!ask why is CPU so high?"), ["!ask", "why?"]
    )
    assert response is not None
    assert llm.last_prompt is not None
    assert "Recent alerts:" in llm.last_prompt
    assert "alert.cpu.threshold_exceeded" in llm.last_prompt
    assert "Top processes by CPU (latest sample):" in llm.last_prompt
    assert "python (pid=111, cpu=45.0%" in llm.last_prompt


@pytest.mark.asyncio
async def test_ask_command_reports_provider_unavailable(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}},
        {},
        llm=_FailingLLMClient(),
    )

    response = await dispatcher.handle_message(_message("!ask why?"), ["!ask", "why?"])
    assert response is not None
    assert "LLM assistant unavailable" in response.text


@pytest.mark.asyncio
async def test_firewall_command_uses_firewall_tool_status_report(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    firewall_tool = _FakeFirewallTool({}, ctx)
    dispatcher = ChatCommandDispatcher(
        config={"chat_adapters": {"discord": {"channel_id": "100"}}},
        app_ctx=ctx,
        scheduler=_FakeScheduler(),  # type: ignore[arg-type]
        tools={"firewall": firewall_tool},
        monitor_registry=_FakeMonitorRegistry(),  # type: ignore[arg-type]
        db=db,
    )

    response = await dispatcher.handle_message(_message("!firewall"), ["!firewall"])
    assert response is not None
    assert "Desired state: MATCH" in response.text


@pytest.mark.asyncio
async def test_firewall_command_handles_status_report_failures(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
    )
    firewall_tool = _FailingFirewallTool({}, ctx)
    dispatcher = ChatCommandDispatcher(
        config={"chat_adapters": {"discord": {"channel_id": "100"}}},
        app_ctx=ctx,
        scheduler=_FakeScheduler(),  # type: ignore[arg-type]
        tools={"firewall": firewall_tool},
        monitor_registry=_FakeMonitorRegistry(),  # type: ignore[arg-type]
        db=db,
    )

    response = await dispatcher.handle_message(_message("!firewall"), ["!firewall"])
    assert response is not None
    assert "Firewall status unavailable" in response.text


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
async def test_cleanup_records_deleted_and_reclaimed_metrics_in_audit(tmp_path: Path) -> None:
    cleanup_dir = tmp_path / "cleanup"
    cleanup_dir.mkdir()
    old_file = cleanup_dir / "old.log"
    old_file.write_text("cleanup-me")

    dispatcher = await _dispatcher(
        tmp_path,
        {
            "chat_adapters": {"discord": {"channel_id": "100"}},
            "tools": {
                "cleanup": {
                    "rules": [
                        {
                            "path": str(cleanup_dir),
                            "pattern": "*.log",
                            "older_than": "00:00:00",
                        }
                    ]
                }
            },
        },
        {},
    )

    confirmation = await dispatcher.handle_message(_message("!cleanup"), ["!cleanup"])
    assert confirmation is not None
    assert "Confirm !cleanup" in confirmation.text

    response = await dispatcher.handle_reaction(_reaction())
    assert response is not None
    assert "Cleanup completed." in response.text
    assert not old_file.exists()

    reaction_call = dispatcher._ctx.audit.append.await_args_list[-1].kwargs  # type: ignore[attr-defined]
    assert reaction_call["action_type"] == "chat_command"
    assert reaction_call["details"]["command"] == "!cleanup"
    assert reaction_call["details"]["cleanup"]["deleted_files"] == 1
    assert reaction_call["details"]["cleanup"]["reclaimed_bytes"] > 0


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
        "system_sentinel.chat.maintenance_utils.os.path.exists",
        lambda path: str(path) == protected_path,
    )

    def _raise_permission_denied(_path: str) -> None:
        raise PermissionError("[Errno 13] Permission denied")

    monkeypatch.setattr(
        "system_sentinel.chat.maintenance_utils.psutil.disk_usage",
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


@pytest.mark.asyncio
async def test_snapshots_command_lists_recent_snapshot_records(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    await db.connection.execute(
        """
        INSERT INTO audit_log
            (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(UTC).isoformat(),
            "snapshot_create",
            "self_update",
            "snapper snapshot created",
            "success",
            json.dumps(
                {
                    "snapshot_id": "42",
                    "label": "pre-update origin/main",
                    "backend": "snapper",
                }
            ),
        ),
    )
    await db.connection.commit()
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

    response = await dispatcher.handle_message(_message("!snapshots"), ["!snapshots"])
    assert response is not None
    assert "Recent snapshots:" in response.text
    assert "pre-update origin/main" in response.text
    assert "snapper" in response.text


@pytest.mark.asyncio
async def test_snapshots_common_typo_alias_is_supported(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    await db.connection.execute(
        """
        INSERT INTO audit_log
            (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(UTC).isoformat(),
            "snapshot_create",
            "self_update",
            "snapper snapshot created",
            "success",
            json.dumps(
                {
                    "snapshot_id": "77",
                    "label": "pre-update origin/main",
                    "backend": "snapper",
                }
            ),
        ),
    )
    await db.connection.commit()
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

    response = await dispatcher.handle_message(_message("!snaphsots"), ["!snaphsots"])
    assert response is not None
    assert "Recent snapshots:" in response.text


@pytest.mark.asyncio
async def test_hardening_command_lists_pass_fail_per_check(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    await db.connection.execute(
        """
        INSERT INTO audit_log
            (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(UTC).isoformat(),
            "tool_run",
            "scheduler",
            "Hardening audit found 1 failing check(s); remediated 1.",
            "failure",
            json.dumps(
                {
                    "tool": "hardening",
                    "checks": [
                        {
                            "id": "ssh_disable_root_login",
                            "title": "SSH root login disabled",
                            "status": "pass",
                            "remediated": False,
                        },
                        {
                            "id": "strong_password_policy",
                            "title": "Strong password policy enforced",
                            "status": "pass",
                            "remediated": True,
                        },
                        {
                            "id": "sysctl_hardening",
                            "title": "Kernel sysctl hardening",
                            "status": "fail",
                            "remediated": False,
                        },
                    ],
                }
            ),
        ),
    )
    await db.connection.commit()
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

    response = await dispatcher.handle_message(_message("!hardening"), ["!hardening"])
    assert response is not None
    assert "Latest hardening audit" in response.text
    assert "PASS | SSH root login disabled" in response.text
    assert "FAIL | Kernel sysctl hardening" in response.text
    assert "auto-remediated" in response.text


@pytest.mark.asyncio
async def test_anomalies_command_lists_recent_login_anomalies(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    login_repo = LoginRepository(db)
    await login_repo.record_anomaly(
        observed_at=datetime.now(UTC),
        anomaly_type="new_user",
        username="alice",
        ip_address="1.2.3.4",
        details={"anomaly_type": "new_user"},
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

    response = await dispatcher.handle_message(_message("!anomalies"), ["!anomalies"])
    assert response is not None
    assert "Recent login anomalies:" in response.text
    assert "new user" in response.text
    assert "alice" in response.text


@pytest.mark.asyncio
async def test_audit_command_lists_recent_entries(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    await db.connection.execute(
        """
        INSERT INTO audit_log
            (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'tool_run', 'scheduler', 'Security update completed', 'success', NULL)
        """,
        (datetime.now(UTC).isoformat(),),
    )
    await db.connection.execute(
        """
        INSERT INTO audit_log
            (timestamp, action_type, source, description, outcome, details_json)
        VALUES (?, 'chat_command', 'chat:discord:123', 'Processed chat command !status.', 'success', NULL)
        """,
        (datetime.now(UTC).isoformat(),),
    )
    await db.connection.commit()

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

    response = await dispatcher.handle_message(_message("!audit"), ["!audit"])
    assert response is not None
    assert "Recent audit entries" in response.text
    assert "chat_command" in response.text
    assert "tool_run" in response.text


@pytest.mark.asyncio
async def test_audit_command_supports_count_option(tmp_path: Path) -> None:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    for i in range(3):
        await db.connection.execute(
            """
            INSERT INTO audit_log
                (timestamp, action_type, source, description, outcome, details_json)
            VALUES (?, 'tool_run', 'scheduler', ?, 'success', NULL)
            """,
            (datetime.now(UTC).isoformat(), f"Entry {i}"),
        )
    await db.connection.commit()
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
        _message("!audit --count 2"), ["!audit", "--count", "2"]
    )
    assert response is not None
    assert "Recent audit entries (last 2):" in response.text
    assert "Entry 2" in response.text
    assert "Entry 1" in response.text
    assert "Entry 0" not in response.text


@pytest.mark.asyncio
async def test_audit_command_rejects_invalid_count(tmp_path: Path) -> None:
    dispatcher = await _dispatcher(
        tmp_path,
        {"chat_adapters": {"discord": {"channel_id": "100"}}},
        {},
    )

    response = await dispatcher.handle_message(
        _message("!audit --count nope"), ["!audit", "--count", "nope"]
    )
    assert response is not None
    assert response.text == "Usage: !audit [--count N]"
