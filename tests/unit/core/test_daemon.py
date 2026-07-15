from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from system_sentinel.core.daemon import (
    DaemonRestartRequested,
    _load_config,
    _register_tool_event_handlers,
    _run_tools_on_startup,
    run_daemon,
)
from system_sentinel.core.exceptions import ConfigError

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# _load_config
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_missing_file_raises_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            _load_config(tmp_path / "missing.yaml")

    def test_valid_yaml_returns_dict(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("chat_adapters:\n  discord:\n    enabled: true\n")
        result = _load_config(config_file)
        assert result == {"chat_adapters": {"discord": {"enabled": True}}}

    def test_invalid_yaml_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("key: [unclosed")
        with pytest.raises(ConfigError, match="parse"):
            _load_config(config_file)

    def test_non_mapping_yaml_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="mapping"):
            _load_config(config_file)

    def test_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        result = _load_config(config_file)
        assert result == {}

    def test_env_reference_resolves_from_environment(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LLM_TOKEN", "super-secret-token")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "chat_adapters": {"discord": {"enabled": True, "token": "env:LLM_TOKEN"}},
                    "llm_providers": {"openai": {"enabled": True, "api_key": "env:LLM_TOKEN"}},
                }
            )
        )

        result = _load_config(config_file)
        assert result["chat_adapters"]["discord"]["token"] == "super-secret-token"
        assert result["llm_providers"]["openai"]["api_key"] == "super-secret-token"

    def test_missing_env_reference_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"chat_adapters": {"discord": {"token": "env:MISSING_TOKEN"}}}))

        with pytest.raises(ConfigError, match="MISSING_TOKEN"):
            _load_config(config_file)

    def test_invalid_env_reference_raises_config_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"chat_adapters": {"discord": {"token": "env:"}}}))

        with pytest.raises(ConfigError, match="expected format"):
            _load_config(config_file)


# ---------------------------------------------------------------------------
# run_daemon
# ---------------------------------------------------------------------------


def _minimal_config(tmp_path: Path) -> Path:
    config = {"chat_adapters": {"discord": {"enabled": True}}, "monitors": {}, "tools": {}}
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump(config))
    return config_file


class TestRunDaemon:
    async def test_config_error_propagates(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            await run_daemon(
                config_path=tmp_path / "nonexistent.yaml",
                db_path=tmp_path / "sentinel.db",
            )

    async def test_daemon_starts_and_stops_on_signal(self, tmp_path: Path) -> None:
        """run_daemon should start components and stop cleanly when stop event fires."""
        config_path = _minimal_config(tmp_path)
        db_path = tmp_path / "sentinel.db"

        stop_event_holder: list[asyncio.Event] = []

        async def fake_wait() -> None:
            # Immediately set the stop event to exit the daemon loop
            if stop_event_holder:
                stop_event_holder[0].set()

        with (
            patch("system_sentinel.core.daemon.DatabaseConnection") as mock_db_cls,
            patch("system_sentinel.core.daemon.MonitorRegistry") as mock_monitor_cls,
            patch("system_sentinel.core.daemon.ChatRegistry") as mock_chat_cls,
            patch("system_sentinel.core.daemon.Scheduler") as mock_sched_cls,
            patch("system_sentinel.core.daemon._discover_tools"),
            patch("system_sentinel.core.daemon.AlertHandler"),
        ):
            mock_db = AsyncMock()
            mock_db_cls.return_value = mock_db

            mock_monitor = MagicMock()
            mock_monitor.start = AsyncMock()
            mock_monitor.stop = AsyncMock()
            mock_monitor_cls.return_value = mock_monitor

            mock_adapter = MagicMock()
            mock_adapter.start = AsyncMock()
            mock_adapter.stop = AsyncMock()
            mock_adapter.send_to_default = AsyncMock()
            mock_adapter.on_message = MagicMock()
            mock_adapter.on_reaction = MagicMock()
            mock_chat = MagicMock()
            mock_chat.adapters = {"discord": mock_adapter}
            mock_chat_cls.return_value = mock_chat

            mock_sched = MagicMock()
            mock_sched_cls.return_value = mock_sched

            # Capture the stop_event and set it immediately so daemon exits
            original_event_class = asyncio.Event

            event_index = 0

            def patched_event() -> asyncio.Event:
                nonlocal event_index
                ev = original_event_class()
                stop_event_holder.append(ev)
                if event_index == 0:
                    ev.set()  # stop_event
                event_index += 1
                return ev

            with patch("system_sentinel.core.daemon.asyncio.Event", side_effect=patched_event):
                await run_daemon(config_path=config_path, db_path=db_path)

        mock_db.connect.assert_awaited_once()
        mock_monitor.start.assert_awaited_once()
        mock_monitor.stop.assert_awaited_once()
        mock_sched.start.assert_called_once()
        mock_sched.stop.assert_called_once()
        mock_adapter.start.assert_awaited_once()
        mock_adapter.stop.assert_awaited_once()
        mock_adapter.send_to_default.assert_awaited_once()
        mock_adapter.on_message.assert_called_once()
        mock_adapter.on_reaction.assert_called_once()
        sent_message = mock_adapter.send_to_default.call_args.args[0]
        assert sent_message.title == "SystemSentinel service started"
        mock_db.close.assert_awaited_once()

    async def test_daemon_requests_restart_after_self_update(self, tmp_path: Path) -> None:
        config_path = _minimal_config(tmp_path)
        db_path = tmp_path / "sentinel.db"

        with (
            patch("system_sentinel.core.daemon.DatabaseConnection") as mock_db_cls,
            patch("system_sentinel.core.daemon.MonitorRegistry") as mock_monitor_cls,
            patch("system_sentinel.core.daemon.ChatRegistry") as mock_chat_cls,
            patch("system_sentinel.core.daemon.Scheduler") as mock_sched_cls,
            patch("system_sentinel.core.daemon._discover_tools"),
            patch("system_sentinel.core.daemon.AlertHandler"),
            patch("system_sentinel.core.daemon.SelfUpdateMonitor") as mock_self_update_cls,
        ):
            mock_db = AsyncMock()
            mock_db_cls.return_value = mock_db

            mock_monitor = MagicMock()
            mock_monitor.start = AsyncMock()
            mock_monitor.stop = AsyncMock()
            mock_monitor_cls.return_value = mock_monitor

            mock_chat = MagicMock()
            mock_chat.adapters = {}
            mock_chat_cls.return_value = mock_chat

            mock_sched = MagicMock()
            mock_sched_cls.return_value = mock_sched

            mock_self_update = MagicMock()
            mock_self_update.enabled = True
            mock_self_update.check_interval_seconds = 30
            mock_self_update.check_and_apply_update = AsyncMock(return_value=True)
            mock_self_update_cls.return_value = mock_self_update

            with pytest.raises(DaemonRestartRequested):
                await run_daemon(config_path=config_path, db_path=db_path)


@pytest.mark.asyncio
async def test_register_tool_event_handlers_runs_tool_on_scheduled_event() -> None:
    bus = MagicMock()
    bus.subscribe = MagicMock()
    tool = MagicMock()
    tool.run = AsyncMock()

    _register_tool_event_handlers(bus, {"firewall": tool})

    bus.subscribe.assert_called_once()
    subscribed_handler = bus.subscribe.call_args.args[1]
    await subscribed_handler("tool.firewall.scheduled", {"source": "scheduler"})
    tool.run.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_tools_on_startup_runs_only_enabled_startup_tools() -> None:
    startup_tool = MagicMock()
    startup_tool.config = {"run_on_startup": True}
    startup_tool.is_enabled.return_value = True
    startup_tool.run = AsyncMock()

    disabled_tool = MagicMock()
    disabled_tool.config = {"run_on_startup": True}
    disabled_tool.is_enabled.return_value = False
    disabled_tool.run = AsyncMock()

    non_startup_tool = MagicMock()
    non_startup_tool.config = {"run_on_startup": False}
    non_startup_tool.is_enabled.return_value = True
    non_startup_tool.run = AsyncMock()

    await _run_tools_on_startup(
        {
            "firewall": startup_tool,
            "packages": disabled_tool,
            "security_update": non_startup_tool,
        }
    )

    startup_tool.run.assert_awaited_once()
    disabled_tool.run.assert_not_awaited()
    non_startup_tool.run.assert_not_awaited()
