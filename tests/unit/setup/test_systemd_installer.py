from __future__ import annotations

import io
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

from system_sentinel.setup.dependency_installer import CommandResult
from system_sentinel.setup.systemd_installer import (
    create_data_dir_step,
    create_sentinel_user_step,
    enable_systemd_service_step,
    fix_install_dir_permissions_step,
    install_systemd_service_step,
    start_systemd_service_step,
)
from system_sentinel.setup.wizard import (
    SetupWizard,
    StepOutcome,
    WizardContext,
)


def _run_step(step_factory, ctx: WizardContext | None = None):
    buf = io.StringIO()
    wizard = SetupWizard(steps=[step_factory()], output=buf)
    results = wizard.run(ctx or WizardContext())
    return results, buf.getvalue()


# ---------------------------------------------------------------------------
# create_sentinel_user_step
# ---------------------------------------------------------------------------


class TestCreateSentinelUserStep:
    def test_step_is_check_safe(self) -> None:
        assert create_sentinel_user_step().check_safe is True

    def test_user_already_exists_succeeds_without_creating(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=0, stdout="sentinel\n", stderr="")
            results, _ = _run_step(create_sentinel_user_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "already exists" in results[0].message.lower()
        # useradd should NOT have been called
        for c in mock_cmd.call_args_list:
            assert "useradd" not in str(c)

    def test_user_missing_creates_user(self) -> None:
        def mock_run(cmd, timeout=300):
            if any("getent" in c for c in cmd):
                return CommandResult(returncode=1, stdout="", stderr="")
            return CommandResult(returncode=0, stdout="", stderr="")

        with patch(
            "system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run
        ) as mock_cmd:
            results, _ = _run_step(create_sentinel_user_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        calls = [str(c) for c in mock_cmd.call_args_list]
        assert any("useradd" in c for c in calls)

    def test_useradd_failure_returns_failure(self) -> None:
        def mock_run(cmd, timeout=300):
            if any("getent" in c for c in cmd):
                return CommandResult(returncode=1, stdout="", stderr="")
            return CommandResult(returncode=1, stdout="", stderr="useradd: permission denied")

        with patch("system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run):
            results, _ = _run_step(create_sentinel_user_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None

    def test_check_only_reports_user_present(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=0, stdout="sentinel\n", stderr="")
            results, _ = _run_step(create_sentinel_user_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_check_only_reports_user_absent(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=1, stdout="", stderr="")
            results, _ = _run_step(create_sentinel_user_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.FAILURE
        assert "not found" in results[0].message.lower()


# ---------------------------------------------------------------------------
# fix_install_dir_permissions_step
# ---------------------------------------------------------------------------


class TestFixInstallDirPermissionsStep:
    def test_step_is_check_safe(self) -> None:
        assert fix_install_dir_permissions_step().check_safe is True

    def test_missing_exec_path_returns_failure(self) -> None:
        with patch(
            "system_sentinel.setup.systemd_installer.shutil.which",
            return_value=None,
        ):
            results, _ = _run_step(fix_install_dir_permissions_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None

    def test_sets_traverse_on_ancestors_and_readable_on_install_dir(self) -> None:
        """chmod o+x on ancestors inside /home and o+rX on install dir."""
        exec_path = "/home/gennon/.local/system-sentinel/.venv/bin/sentinel"

        chmod_calls: list[list[str]] = []

        def mock_run(cmd, timeout=300):
            chmod_calls.append(list(cmd))
            return CommandResult(returncode=0, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.shutil.which",
                return_value=exec_path,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.run_command",
                side_effect=mock_run,
            ),
        ):
            results, _ = _run_step(fix_install_dir_permissions_step)

        assert results[0].outcome == StepOutcome.SUCCESS

        # o+x should have been applied to ancestor dirs inside /home
        traverse_targets = [c[3] for c in chmod_calls if "o+x" in c]
        assert "/home/gennon" in traverse_targets
        assert "/home/gennon/.local" in traverse_targets

        # o+rX should have been applied recursively to the install dir
        recursive_targets = [c for c in chmod_calls if "-R" in c and "o+rX" in c]
        assert any("/home/gennon/.local/system-sentinel" in c for c in recursive_targets)

    def test_chmod_ancestor_failure_returns_failure(self) -> None:
        exec_path = "/home/gennon/.local/system-sentinel/.venv/bin/sentinel"

        def mock_run(cmd, timeout=300):
            return CommandResult(returncode=1, stdout="", stderr="permission denied")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.shutil.which",
                return_value=exec_path,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.run_command",
                side_effect=mock_run,
            ),
        ):
            results, _ = _run_step(fix_install_dir_permissions_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None

    def test_chmod_install_dir_failure_returns_failure(self) -> None:
        exec_path = "/home/gennon/.local/system-sentinel/.venv/bin/sentinel"
        call_count = 0

        def mock_run(cmd, timeout=300):
            nonlocal call_count
            call_count += 1
            # Ancestor o+x calls succeed; recursive o+rX call fails
            if "-R" in cmd:
                return CommandResult(returncode=1, stdout="", stderr="permission denied")
            return CommandResult(returncode=0, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.shutil.which",
                return_value=exec_path,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.run_command",
                side_effect=mock_run,
            ),
        ):
            results, _ = _run_step(fix_install_dir_permissions_step)

        assert results[0].outcome == StepOutcome.FAILURE

    def test_check_only_exec_world_executable_succeeds(self, tmp_path) -> None:
        sentinel_bin = tmp_path / "sentinel"
        sentinel_bin.write_text("#!/bin/sh\necho hi")
        sentinel_bin.chmod(0o755)  # world-executable

        with patch(
            "system_sentinel.setup.systemd_installer.shutil.which",
            return_value=str(sentinel_bin),
        ):
            results, _ = _run_step(fix_install_dir_permissions_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_check_only_exec_not_world_executable_fails(self, tmp_path) -> None:
        sentinel_bin = tmp_path / "sentinel"
        sentinel_bin.write_text("#!/bin/sh\necho hi")
        sentinel_bin.chmod(0o750)  # no world execute

        with patch(
            "system_sentinel.setup.systemd_installer.shutil.which",
            return_value=str(sentinel_bin),
        ):
            results, _ = _run_step(fix_install_dir_permissions_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.FAILURE

    def test_install_dir_not_under_home_skips_ancestors(self) -> None:
        """When installed in /opt, no ancestor chmod calls are needed."""
        exec_path = "/opt/system-sentinel/.venv/bin/sentinel"

        chmod_calls: list[list[str]] = []

        def mock_run(cmd, timeout=300):
            chmod_calls.append(list(cmd))
            return CommandResult(returncode=0, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.shutil.which",
                return_value=exec_path,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.run_command",
                side_effect=mock_run,
            ),
        ):
            results, _ = _run_step(fix_install_dir_permissions_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        # Only the recursive o+rX call should be present; no o+x ancestor calls
        traverse_calls = [c for c in chmod_calls if "o+x" in c and "-R" not in c]
        assert len(traverse_calls) == 0


# ---------------------------------------------------------------------------
# create_data_dir_step
# ---------------------------------------------------------------------------


class TestCreateDataDirStep:
    def test_step_is_check_safe(self) -> None:
        assert create_data_dir_step().check_safe is True

    def test_check_only_both_dirs_exist(self, tmp_path) -> None:
        with (
            patch(
                "system_sentinel.setup.systemd_installer.DATA_DIR",
                tmp_path / "sentinel",
            ),
            patch(
                "system_sentinel.setup.systemd_installer.CONFIG_DIR",
                tmp_path / "etc-sentinel",
            ),
        ):
            (tmp_path / "sentinel").mkdir()
            (tmp_path / "etc-sentinel").mkdir()
            results, _ = _run_step(create_data_dir_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_check_only_missing_dir_fails(self, tmp_path) -> None:
        with (
            patch(
                "system_sentinel.setup.systemd_installer.DATA_DIR",
                tmp_path / "sentinel",
            ),
            patch(
                "system_sentinel.setup.systemd_installer.CONFIG_DIR",
                tmp_path / "etc-sentinel",
            ),
        ):
            # Neither directory exists
            results, _ = _run_step(create_data_dir_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.FAILURE
        assert "missing" in results[0].message.lower()

    def test_creates_and_chowns_both_dirs(self, tmp_path) -> None:
        cmds: list[list[str]] = []

        def mock_run(cmd, timeout=300):
            cmds.append(list(cmd))
            return CommandResult(returncode=0, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.DATA_DIR",
                tmp_path / "sentinel",
            ),
            patch(
                "system_sentinel.setup.systemd_installer.CONFIG_DIR",
                tmp_path / "etc-sentinel",
            ),
            patch("system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run),
        ):
            results, _ = _run_step(create_data_dir_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        mkdir_cmds = [c for c in cmds if any(s.endswith("mkdir") for s in c)]
        chown_cmds = [c for c in cmds if any(s.endswith("chown") for s in c)]
        mkdir_targets = [c[3] for c in mkdir_cmds]
        chown_targets = [c[3] for c in chown_cmds]
        assert any("sentinel" in t for t in mkdir_targets)
        assert any("etc-sentinel" in t for t in mkdir_targets)
        assert any("sentinel" in t for t in chown_targets)
        chown_owners = [c[2] for c in chown_cmds]
        assert all(o == "sentinel:sentinel" for o in chown_owners)

    def test_mkdir_failure_returns_failure(self, tmp_path) -> None:
        def mock_run(cmd, timeout=300):
            if any(s.endswith("mkdir") for s in cmd):
                return CommandResult(returncode=1, stdout="", stderr="permission denied")
            return CommandResult(returncode=0, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.DATA_DIR",
                tmp_path / "sentinel",
            ),
            patch(
                "system_sentinel.setup.systemd_installer.CONFIG_DIR",
                tmp_path / "etc-sentinel",
            ),
            patch("system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run),
        ):
            results, _ = _run_step(create_data_dir_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None

    def test_chown_failure_returns_failure(self, tmp_path) -> None:
        def mock_run(cmd, timeout=300):
            if any("chown" in s for s in cmd):
                return CommandResult(returncode=1, stdout="", stderr="permission denied")
            return CommandResult(returncode=0, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.DATA_DIR",
                tmp_path / "sentinel",
            ),
            patch(
                "system_sentinel.setup.systemd_installer.CONFIG_DIR",
                tmp_path / "etc-sentinel",
            ),
            patch("system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run),
        ):
            results, _ = _run_step(create_data_dir_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None


# ---------------------------------------------------------------------------
# install_systemd_service_step
# ---------------------------------------------------------------------------


class TestInstallSystemdServiceStep:
    def test_step_is_check_safe(self) -> None:
        assert install_systemd_service_step().check_safe is True

    def test_check_only_service_file_present(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.Path.exists", return_value=True):
            results, _ = _run_step(install_systemd_service_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "found" in results[0].message.lower()

    def test_check_only_service_file_absent(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.Path.exists", return_value=False):
            results, _ = _run_step(install_systemd_service_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.FAILURE
        assert "not found" in results[0].message.lower()

    def test_installs_service_file_with_exec_path(self, tmp_path: Path) -> None:
        import subprocess as _sp

        service_template = tmp_path / "sentinel.service"
        service_template.write_text("[Service]\nExecStart={exec_path} run\n")
        dest = tmp_path / "sentinel.service.installed"

        def fake_tee(cmd: list[str], input: str, **kwargs: object) -> _sp.CompletedProcess[str]:
            # Simulate sudo tee writing to dest
            dest.write_text(input)
            return _sp.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.SERVICE_TEMPLATE_PATH",
                service_template,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.SERVICE_INSTALL_PATH",
                dest,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.shutil.which",
                return_value="/usr/local/bin/sentinel",
            ),
            patch("system_sentinel.setup.systemd_installer.subprocess.run", side_effect=fake_tee),
            patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd,
        ):
            mock_cmd.return_value = CommandResult(returncode=0, stdout="", stderr="")
            results, _ = _run_step(install_systemd_service_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "/usr/local/bin/sentinel run" in dest.read_text()
        # daemon-reload should have been called
        calls = [str(c) for c in mock_cmd.call_args_list]
        assert any("daemon-reload" in c for c in calls)

    def test_missing_exec_path_returns_failure(self, tmp_path: Path) -> None:
        service_template = tmp_path / "sentinel.service"
        service_template.write_text("[Service]\nExecStart={exec_path} run\n")

        with (
            patch(
                "system_sentinel.setup.systemd_installer.SERVICE_TEMPLATE_PATH",
                service_template,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.shutil.which",
                return_value=None,
            ),
        ):
            results, _ = _run_step(install_systemd_service_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None

    def test_daemon_reload_failure_returns_failure(self, tmp_path: Path) -> None:
        service_template = tmp_path / "sentinel.service"
        service_template.write_text("[Service]\nExecStart={exec_path} run\n")
        dest = tmp_path / "sentinel.service.installed"

        with (
            patch(
                "system_sentinel.setup.systemd_installer.SERVICE_TEMPLATE_PATH",
                service_template,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.SERVICE_INSTALL_PATH",
                dest,
            ),
            patch(
                "system_sentinel.setup.systemd_installer.shutil.which",
                return_value="/usr/local/bin/sentinel",
            ),
            patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd,
        ):
            mock_cmd.return_value = CommandResult(
                returncode=1, stdout="", stderr="Failed to reload"
            )
            results, _ = _run_step(install_systemd_service_step)

        assert results[0].outcome == StepOutcome.FAILURE


# ---------------------------------------------------------------------------
# enable_systemd_service_step
# ---------------------------------------------------------------------------


class TestEnableSystemdServiceStep:
    def test_step_is_check_safe(self) -> None:
        assert enable_systemd_service_step().check_safe is True

    def test_check_only_reports_enabled(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=0, stdout="enabled\n", stderr="")
            results, _ = _run_step(enable_systemd_service_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "enabled" in results[0].message.lower()

    def test_check_only_reports_not_enabled(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=1, stdout="disabled\n", stderr="")
            results, _ = _run_step(enable_systemd_service_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.FAILURE

    def test_already_enabled_skips_enable(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=0, stdout="enabled\n", stderr="")
            results, _ = _run_step(enable_systemd_service_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "already enabled" in results[0].message.lower()
        # Only one call (is-enabled check), no enable call
        assert mock_cmd.call_count == 1

    def test_not_enabled_runs_enable(self) -> None:
        call_count = 0

        def mock_run(cmd, timeout=300):
            nonlocal call_count
            call_count += 1
            if "is-enabled" in cmd:
                return CommandResult(returncode=1, stdout="disabled\n", stderr="")
            return CommandResult(returncode=0, stdout="", stderr="")

        with patch(
            "system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run
        ) as mock_cmd:
            results, _ = _run_step(enable_systemd_service_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        calls = [str(c) for c in mock_cmd.call_args_list]
        assert any("enable" in c and "is-enabled" not in c for c in calls)

    def test_enable_failure_returns_failure(self) -> None:
        def mock_run(cmd, timeout=300):
            if "is-enabled" in cmd:
                return CommandResult(returncode=1, stdout="disabled\n", stderr="")
            return CommandResult(returncode=1, stdout="", stderr="Failed to enable")

        with patch("system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run):
            results, _ = _run_step(enable_systemd_service_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None


# ---------------------------------------------------------------------------
# start_systemd_service_step
# ---------------------------------------------------------------------------


class TestStartSystemdServiceStep:
    def test_step_is_check_safe(self) -> None:
        assert start_systemd_service_step().check_safe is True

    def test_check_only_reports_active(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=0, stdout="active\n", stderr="")
            results, _ = _run_step(start_systemd_service_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "active" in results[0].message.lower()

    def test_check_only_reports_inactive(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=1, stdout="inactive\n", stderr="")
            results, _ = _run_step(start_systemd_service_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.FAILURE

    def test_already_active_skips_start(self) -> None:
        with patch("system_sentinel.setup.systemd_installer.run_command") as mock_cmd:
            mock_cmd.return_value = CommandResult(returncode=0, stdout="active\n", stderr="")
            results, _ = _run_step(start_systemd_service_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "already" in results[0].message.lower()
        assert mock_cmd.call_count == 1

    def test_start_then_becomes_active(self) -> None:
        responses = iter(
            [
                CommandResult(returncode=1, stdout="inactive\n", stderr=""),  # initial is-active
                CommandResult(returncode=0, stdout="", stderr=""),  # start
                CommandResult(returncode=0, stdout="active\n", stderr=""),  # poll is-active
            ]
        )

        with patch(
            "system_sentinel.setup.systemd_installer.run_command",
            side_effect=lambda cmd, **kw: next(responses),
        ):
            results, _ = _run_step(start_systemd_service_step)

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_start_failure_returns_failure(self) -> None:
        def mock_run(cmd, timeout=300):
            if "is-active" in cmd:
                return CommandResult(returncode=1, stdout="inactive\n", stderr="")
            return CommandResult(returncode=1, stdout="", stderr="Failed to start")

        with patch("system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run):
            results, _ = _run_step(start_systemd_service_step)

        assert results[0].outcome == StepOutcome.FAILURE

    def test_poll_timeout_returns_failure(self) -> None:
        call_count = 0

        def mock_run(cmd, timeout=300):
            nonlocal call_count
            call_count += 1
            if "start" in cmd and "is-active" not in cmd:
                return CommandResult(returncode=0, stdout="", stderr="")
            # Never becomes active
            return CommandResult(returncode=1, stdout="activating\n", stderr="")

        with (
            patch("system_sentinel.setup.systemd_installer.run_command", side_effect=mock_run),
            patch("system_sentinel.setup.systemd_installer.time.sleep"),
        ):
            results, _ = _run_step(start_systemd_service_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert (
            "timed out" in results[0].message.lower()
            or "timed out" in (results[0].error or "").lower()
        )
