from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from system_sentinel.core.daemon import _load_config, run_daemon
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
        config_file.write_text("chat:\n  provider: discord\n")
        result = _load_config(config_file)
        assert result == {"chat": {"provider": "discord"}}

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


# ---------------------------------------------------------------------------
# run_daemon
# ---------------------------------------------------------------------------


def _minimal_config(tmp_path: Path) -> Path:
    config = {"chat": {"provider": "discord"}, "monitors": {}, "tools": {}}
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

            mock_chat = MagicMock()
            mock_chat.adapters = {}
            mock_chat_cls.return_value = mock_chat

            mock_sched = MagicMock()
            mock_sched_cls.return_value = mock_sched

            # Capture the stop_event and set it immediately so daemon exits
            original_event_class = asyncio.Event

            def patched_event() -> asyncio.Event:
                ev = original_event_class()
                stop_event_holder.append(ev)
                ev.set()  # pre-set so the await stop_event.wait() returns immediately
                return ev

            with patch("system_sentinel.core.daemon.asyncio.Event", side_effect=patched_event):
                await run_daemon(config_path=config_path, db_path=db_path)

        mock_db.connect.assert_awaited_once()
        mock_monitor.start.assert_awaited_once()
        mock_monitor.stop.assert_awaited_once()
        mock_sched.start.assert_called_once()
        mock_sched.stop.assert_called_once()
        mock_db.close.assert_awaited_once()
