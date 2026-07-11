from __future__ import annotations

import sys
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from system_sentinel.cli.main import _restart_exec_args, cli
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


class TestRestartExecArgs:
    def test_prefers_existing_absolute_launcher(self) -> None:
        with (
            patch.object(sys, "argv", ["/tmp/sentinel", "run"]),
            patch("system_sentinel.cli.main.os.path.isabs", return_value=True),
            patch("system_sentinel.cli.main.os.path.exists", return_value=True),
        ):
            executable, args = _restart_exec_args()

        assert executable == "/tmp/sentinel"
        assert args == ["/tmp/sentinel", "run"]

    def test_resolves_launcher_via_path_lookup(self) -> None:
        with (
            patch.object(sys, "argv", ["sentinel", "run"]),
            patch("system_sentinel.cli.main.os.path.isabs", return_value=False),
            patch("system_sentinel.cli.main.shutil.which", return_value="/usr/local/bin/sentinel"),
        ):
            executable, args = _restart_exec_args()

        assert executable == "/usr/local/bin/sentinel"
        assert args == ["/usr/local/bin/sentinel", "run"]

    def test_falls_back_to_python_interpreter(self) -> None:
        with (
            patch.object(sys, "argv", ["sentinel", "run"]),
            patch("system_sentinel.cli.main.os.path.isabs", return_value=False),
            patch("system_sentinel.cli.main.shutil.which", return_value=None),
            patch.object(sys, "executable", "/usr/bin/python3"),
        ):
            executable, args = _restart_exec_args()

        assert executable == "/usr/bin/python3"
        assert args == ["/usr/bin/python3", "sentinel", "run"]
