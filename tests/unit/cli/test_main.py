from __future__ import annotations

from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from system_sentinel.cli.main import cli
from system_sentinel.core.daemon import DaemonRestartRequested
from system_sentinel.core.exceptions import ConfigError


class TestRunCommand:
    def test_run_reexecs_process_on_restart_request(self) -> None:
        runner = CliRunner()

        with (
            patch(
                "system_sentinel.cli.main.run_daemon",
                AsyncMock(side_effect=DaemonRestartRequested),
            ),
            patch(
                "system_sentinel.cli.main._restart_current_process",
                side_effect=SystemExit(0),
            ) as mock_restart,
        ):
            result = runner.invoke(cli, ["run"])

        assert result.exit_code == 0
        mock_restart.assert_called_once()

    def test_run_reports_error_when_restart_exec_fails(self) -> None:
        runner = CliRunner()

        with (
            patch(
                "system_sentinel.cli.main.run_daemon",
                AsyncMock(side_effect=DaemonRestartRequested),
            ),
            patch(
                "system_sentinel.cli.main._restart_current_process",
                side_effect=OSError("exec failed"),
            ),
        ):
            result = runner.invoke(cli, ["run"])

        assert result.exit_code == 1
        assert "Failed to restart daemon process: exec failed" in result.output

    def test_run_reports_config_error(self) -> None:
        runner = CliRunner()

        with patch(
            "system_sentinel.cli.main.run_daemon",
            AsyncMock(side_effect=ConfigError("bad config")),
        ):
            result = runner.invoke(cli, ["run"])

        assert result.exit_code == 1
        assert "Configuration error: bad config" in result.output
