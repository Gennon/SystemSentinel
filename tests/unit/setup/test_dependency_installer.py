from __future__ import annotations

import io
import subprocess
import sys
from unittest.mock import patch

from system_sentinel.setup.dependency_installer import (
    CommandResult,
    SetupRequirements,
    check_platform_step,
    install_python_packages_step,
    install_system_packages_step,
    run_command,
)
from system_sentinel.setup.wizard import (
    SetupWizard,
    StepOutcome,
    WizardContext,
)

FAKE_REQS = SetupRequirements(
    supported_os=["Linux"],
    supported_architectures=["x86_64", "aarch64"],
    system_packages=["iproute2", "sqlite3", "curl"],
    python_modules=["pydantic", "psutil", "click"],
)


def _run_step(step_factory, ctx: WizardContext | None = None):
    """Helper: run a single step through the wizard and return (results, output)."""
    buf = io.StringIO()
    wizard = SetupWizard(steps=[step_factory()], output=buf)
    results = wizard.run(ctx or WizardContext())
    return results, buf.getvalue()


# ---------------------------------------------------------------------------
# run_command helper
# ---------------------------------------------------------------------------


class TestRunCommand:
    def test_returns_command_result_on_success(self) -> None:
        with patch("system_sentinel.setup.dependency_installer.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["/usr/bin/echo", "hi"],
                returncode=0,
                stdout="hi\n",
                stderr="",
            )
            result = run_command(["/usr/bin/echo", "hi"])

        assert isinstance(result, CommandResult)
        assert result.returncode == 0
        assert result.stdout == "hi\n"
        assert result.stderr == ""

    def test_returns_nonzero_on_failure(self) -> None:
        with patch("system_sentinel.setup.dependency_installer.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["/usr/bin/false"],
                returncode=1,
                stdout="",
                stderr="error occurred",
            )
            result = run_command(["/usr/bin/false"])

        assert result.returncode == 1
        assert result.stderr == "error occurred"

    def test_timeout_returns_failure(self) -> None:
        with patch("system_sentinel.setup.dependency_installer.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="/usr/bin/sleep", timeout=10)
            result = run_command(["/usr/bin/sleep", "999"], timeout=10)

        assert result.returncode == -1
        assert "timed out" in result.stderr.lower()


# ---------------------------------------------------------------------------
# check_platform_step
# ---------------------------------------------------------------------------


class TestCheckPlatformStep:
    def test_linux_x86_64_succeeds(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.system", return_value="Linux"
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.machine",
                return_value="x86_64",
            ),
        ):
            results, _ = _run_step(check_platform_step)

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_linux_aarch64_succeeds(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.system", return_value="Linux"
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.machine",
                return_value="aarch64",
            ),
        ):
            results, _ = _run_step(check_platform_step)

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_unsupported_os_fails(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.system", return_value="Darwin"
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.machine",
                return_value="x86_64",
            ),
        ):
            results, _ = _run_step(check_platform_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert "Linux" in (results[0].error or "")

    def test_unsupported_arch_fails(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.system", return_value="Linux"
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.machine",
                return_value="armv7l",
            ),
        ):
            results, _ = _run_step(check_platform_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert "x86_64" in (results[0].error or "") or "aarch64" in (results[0].error or "")

    def test_step_is_check_safe(self) -> None:
        step = check_platform_step()
        assert step.check_safe is True

    def test_runs_in_check_only_mode(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.system", return_value="Linux"
            ),
            patch(
                "system_sentinel.setup.dependency_installer.platform.machine",
                return_value="x86_64",
            ),
        ):
            results, _ = _run_step(check_platform_step, WizardContext(check_only=True))

        assert results[0].outcome == StepOutcome.SUCCESS


# ---------------------------------------------------------------------------
# install_system_packages_step
# ---------------------------------------------------------------------------


class TestInstallSystemPackagesStep:
    def test_step_is_not_check_safe(self) -> None:
        step = install_system_packages_step()
        assert step.check_safe is False

    def test_skipped_in_check_only_mode(self) -> None:
        results, _ = _run_step(install_system_packages_step, WizardContext(check_only=True))
        assert results[0].outcome == StepOutcome.SKIPPED

    def test_no_package_manager_found_fails(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch("system_sentinel.setup.dependency_installer.Path.exists", return_value=False),
        ):
            results, _ = _run_step(install_system_packages_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert "package manager" in results[0].message.lower()

    def test_apt_detected_and_used(self) -> None:
        def path_exists_side_effect(self):
            return str(self) == "/usr/bin/apt-get"

        def mock_run_command(cmd, timeout=300):
            if "install" in cmd:
                return CommandResult(returncode=0, stdout="", stderr="")
            # dpkg -s returns 1 (not installed)
            return CommandResult(returncode=1, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.Path.exists",
                path_exists_side_effect,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.run_command",
                side_effect=mock_run_command,
            ) as mock_cmd,
        ):
            results, _ = _run_step(install_system_packages_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        calls = [str(c) for c in mock_cmd.call_args_list]
        assert any("apt-get" in c for c in calls)

    def test_dnf_detected_when_apt_missing(self) -> None:
        def path_exists_side_effect(self):
            return str(self) == "/usr/bin/dnf"

        def mock_run_command(cmd, timeout=300):
            if "install" in cmd:
                return CommandResult(returncode=0, stdout="", stderr="")
            # rpm -q returns 1 (not installed)
            return CommandResult(returncode=1, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.Path.exists",
                path_exists_side_effect,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.run_command",
                side_effect=mock_run_command,
            ) as mock_cmd,
        ):
            results, _ = _run_step(install_system_packages_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        calls = [str(c) for c in mock_cmd.call_args_list]
        assert any("dnf" in c for c in calls)

    def test_pacman_detected_when_others_missing(self) -> None:
        def path_exists_side_effect(self):
            return str(self) == "/usr/bin/pacman"

        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.Path.exists",
                path_exists_side_effect,
            ),
            patch("system_sentinel.setup.dependency_installer.run_command") as mock_cmd,
        ):
            mock_cmd.return_value = CommandResult(returncode=0, stdout="", stderr="")
            results, _ = _run_step(install_system_packages_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        calls = [str(c) for c in mock_cmd.call_args_list]
        assert any("pacman" in c for c in calls)

    def test_already_installed_packages_are_skipped(self) -> None:
        def path_exists_side_effect(self):
            return str(self) == "/usr/bin/apt-get"

        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.Path.exists",
                path_exists_side_effect,
            ),
            patch("system_sentinel.setup.dependency_installer.run_command") as mock_cmd,
        ):
            # dpkg -s returns 0 for all packages (all installed)
            mock_cmd.return_value = CommandResult(returncode=0, stdout="", stderr="")
            results, _ = _run_step(install_system_packages_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "already installed" in results[0].message.lower()

    def test_installation_failure_reports_error(self) -> None:
        def path_exists_side_effect(self):
            return str(self) == "/usr/bin/apt-get"

        def mock_run_command(cmd, timeout=300):
            if "install" in cmd:
                return CommandResult(
                    returncode=1, stdout="", stderr="E: Unable to locate package foo"
                )
            # dpkg -s returns 1 (not installed)
            return CommandResult(returncode=1, stdout="", stderr="")

        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.Path.exists",
                path_exists_side_effect,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.run_command",
                side_effect=mock_run_command,
            ),
        ):
            results, _ = _run_step(install_system_packages_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None
        assert "Unable to locate" in results[0].error


# ---------------------------------------------------------------------------
# install_python_packages_step
# ---------------------------------------------------------------------------


class TestInstallPythonPackagesStep:
    def test_step_is_not_check_safe(self) -> None:
        step = install_python_packages_step()
        assert step.check_safe is False

    def test_skipped_in_check_only_mode(self) -> None:
        results, _ = _run_step(install_python_packages_step, WizardContext(check_only=True))
        assert results[0].outcome == StepOutcome.SKIPPED

    def test_all_deps_importable_succeeds(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.importlib.import_module"
            ) as mock_import,
        ):
            mock_import.return_value = None
            results, _ = _run_step(install_python_packages_step)

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_missing_dep_fails_with_name(self) -> None:
        def import_side_effect(name):
            if name == "psutil":
                raise ImportError(f"No module named '{name}'")
            return None

        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.importlib.import_module",
                side_effect=import_side_effect,
            ),
        ):
            results, _ = _run_step(install_python_packages_step)

        assert results[0].outcome == StepOutcome.FAILURE
        assert "psutil" in results[0].message

    def test_reports_virtualenv_active(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.importlib.import_module",
                return_value=None,
            ),
            patch.object(sys, "prefix", "/home/user/.venv"),
            patch.object(sys, "base_prefix", "/usr"),
        ):
            results, _ = _run_step(install_python_packages_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "virtualenv active" in results[0].message

    def test_reports_no_virtualenv(self) -> None:
        with (
            patch(
                "system_sentinel.setup.dependency_installer.load_setup_requirements",
                return_value=FAKE_REQS,
            ),
            patch(
                "system_sentinel.setup.dependency_installer.importlib.import_module",
                return_value=None,
            ),
            patch.object(sys, "prefix", "/usr"),
            patch.object(sys, "base_prefix", "/usr"),
        ):
            results, _ = _run_step(install_python_packages_step)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "no virtualenv" in results[0].message
