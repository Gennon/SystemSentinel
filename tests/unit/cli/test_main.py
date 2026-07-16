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


class TestDashboardCommand:
    def test_dashboard_uses_default_refresh_without_config(self) -> None:
        runner = CliRunner()
        with patch("system_sentinel.cli.main.launch_dashboard") as mock_launch:
            result = runner.invoke(
                cli,
                [
                    "dashboard",
                    "--config-path",
                    "/tmp/non-existent-config.yaml",
                    "--db-path",
                    "/tmp/sentinel.db",
                ],
            )

        assert result.exit_code == 0
        mock_launch.assert_called_once()
        kwargs = mock_launch.call_args.kwargs
        assert kwargs["refresh_interval_seconds"] == 5.0
        assert kwargs["config"] == {}

    def test_dashboard_reads_refresh_interval_from_config(self, tmp_path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("dashboard:\n  refresh_interval: '00:00:07'\n")

        runner = CliRunner()
        with patch("system_sentinel.cli.main.launch_dashboard") as mock_launch:
            result = runner.invoke(
                cli,
                [
                    "dashboard",
                    "--config-path",
                    str(config_path),
                    "--db-path",
                    "/tmp/sentinel.db",
                ],
            )

        assert result.exit_code == 0
        mock_launch.assert_called_once()
        kwargs = mock_launch.call_args.kwargs
        assert kwargs["refresh_interval_seconds"] == 7.0

    def test_dashboard_cli_option_overrides_config_refresh(self, tmp_path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text("dashboard:\n  refresh_interval: '00:00:07'\n")

        runner = CliRunner()
        with patch("system_sentinel.cli.main.launch_dashboard") as mock_launch:
            result = runner.invoke(
                cli,
                [
                    "dashboard",
                    "--config-path",
                    str(config_path),
                    "--db-path",
                    "/tmp/sentinel.db",
                    "--refresh-interval",
                    "00:00:02",
                ],
            )

        assert result.exit_code == 0
        mock_launch.assert_called_once()
        kwargs = mock_launch.call_args.kwargs
        assert kwargs["refresh_interval_seconds"] == 2.0

    def test_dashboard_rejects_invalid_cli_refresh_interval(self) -> None:
        runner = CliRunner()
        with patch("system_sentinel.cli.main.launch_dashboard") as mock_launch:
            result = runner.invoke(
                cli,
                [
                    "dashboard",
                    "--config-path",
                    "/tmp/non-existent-config.yaml",
                    "--db-path",
                    "/tmp/sentinel.db",
                    "--refresh-interval",
                    "5s",
                ],
            )

        assert result.exit_code == 1
        assert "Invalid --refresh-interval value." in result.output
        mock_launch.assert_not_called()
