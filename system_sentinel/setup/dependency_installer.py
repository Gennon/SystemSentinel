from __future__ import annotations

from dataclasses import dataclass
import importlib
from pathlib import Path
import platform
import subprocess
import sys

import yaml

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult

SETUP_REQUIREMENTS_PATH = Path(__file__).resolve().parents[2] / "config" / "setup_requirements.yaml"

PACKAGE_MANAGER_PATHS = (
    Path("/usr/bin/apt-get"),
    Path("/usr/bin/dnf"),
    Path("/usr/bin/pacman"),
)


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class SetupRequirements:
    supported_os: list[str]
    supported_architectures: list[str]
    system_packages: list[str]
    python_modules: list[str]


def load_setup_requirements(path: Path = SETUP_REQUIREMENTS_PATH) -> SetupRequirements:
    """Load setup requirements from the YAML config file."""
    with path.open() as f:
        data = yaml.safe_load(f)

    platforms = data["supported_platforms"]
    return SetupRequirements(
        supported_os=platforms["os"],
        supported_architectures=platforms["architectures"],
        system_packages=data["system_packages"],
        python_modules=data["python_modules"],
    )


def run_command(cmd: list[str], timeout: int = 300) -> CommandResult:
    """Run a subprocess and return the result. Never raises."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return CommandResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=f"Command timed out after {timeout}s: {' '.join(cmd)}",
        )


def _detect_package_manager() -> str | None:
    """Return the path to the first available package manager, or None."""
    for pm_path in PACKAGE_MANAGER_PATHS:
        if pm_path.exists():
            return str(pm_path)
    return None


def _check_package_installed(manager: str, package: str) -> bool:
    """Return True if a system package is already installed."""
    if "apt-get" in manager:
        result = run_command(["/usr/bin/dpkg", "-s", package])
    elif "dnf" in manager:
        result = run_command(["/usr/bin/rpm", "-q", package])
    elif "pacman" in manager:
        result = run_command(["/usr/bin/pacman", "-Q", package])
    else:
        return False
    return result.returncode == 0


def _install_packages(manager: str, packages: list[str]) -> CommandResult:
    """Install packages using the detected package manager."""
    if "apt-get" in manager or "dnf" in manager:
        cmd = [manager, "install", "-y", *packages]
    elif "pacman" in manager:
        cmd = [manager, "-S", "--noconfirm", *packages]
    else:
        return CommandResult(returncode=1, stdout="", stderr="Unknown package manager")
    return run_command(cmd)


def check_platform_step() -> WizardStep:
    """Return a WizardStep that validates OS and architecture."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        reqs = load_setup_requirements()
        os_name = platform.system()
        arch = platform.machine()

        if os_name not in reqs.supported_os:
            return WizardStepResult(
                step_name="check_platform",
                outcome=StepOutcome.FAILURE,
                message=f"Unsupported OS: {os_name}",
                error=f"SystemSentinel requires: {', '.join(reqs.supported_os)}. "
                f"Detected: {os_name} {arch}",
            )

        if arch not in reqs.supported_architectures:
            return WizardStepResult(
                step_name="check_platform",
                outcome=StepOutcome.FAILURE,
                message=f"Unsupported architecture: {arch}",
                error=f"Supported architectures: {', '.join(reqs.supported_architectures)}. "
                f"Detected: {arch}",
            )

        return WizardStepResult(
            step_name="check_platform",
            outcome=StepOutcome.SUCCESS,
            message=f"Linux {arch}",
        )

    return WizardStep(
        name="check_platform",
        description="Validate OS and CPU architecture",
        runner=runner,
        check_safe=True,
    )


def install_system_packages_step() -> WizardStep:
    """Return a WizardStep that installs required system packages."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        reqs = load_setup_requirements()
        manager = _detect_package_manager()

        if manager is None:
            return WizardStepResult(
                step_name="install_system_packages",
                outcome=StepOutcome.FAILURE,
                message="No supported package manager found",
                error="Could not find apt-get, dnf, or pacman.",
            )

        missing: list[str] = []
        already_installed: list[str] = []

        for package in reqs.system_packages:
            if _check_package_installed(manager, package):
                already_installed.append(package)
            else:
                missing.append(package)

        if not missing:
            return WizardStepResult(
                step_name="install_system_packages",
                outcome=StepOutcome.SUCCESS,
                message=f"All {len(already_installed)} system packages already installed.",
            )

        result = _install_packages(manager, missing)
        if result.returncode != 0:
            return WizardStepResult(
                step_name="install_system_packages",
                outcome=StepOutcome.FAILURE,
                message=f"Failed to install: {', '.join(missing)}",
                error=result.stderr.strip() or result.stdout.strip(),
            )

        return WizardStepResult(
            step_name="install_system_packages",
            outcome=StepOutcome.SUCCESS,
            message=f"Installed {', '.join(missing)}. "
            f"Already present: {', '.join(already_installed) or 'none'}.",
        )

    return WizardStep(
        name="install_system_packages",
        description="Install required system packages",
        runner=runner,
        check_safe=False,
    )


def install_python_packages_step() -> WizardStep:
    """Return a WizardStep that verifies Python dependencies are importable."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        reqs = load_setup_requirements()
        missing: list[str] = []

        for module_name in reqs.python_modules:
            try:
                importlib.import_module(module_name)
            except ImportError:
                missing.append(module_name)

        if missing:
            return WizardStepResult(
                step_name="install_python_packages",
                outcome=StepOutcome.FAILURE,
                message=f"Missing Python packages: {', '.join(missing)}",
                error="Install with: pip install system-sentinel",
            )

        in_venv = sys.prefix != sys.base_prefix
        venv_note = " (virtualenv active)" if in_venv else " (no virtualenv detected)"

        return WizardStepResult(
            step_name="install_python_packages",
            outcome=StepOutcome.SUCCESS,
            message=f"All {len(reqs.python_modules)} Python dependencies available{venv_note}.",
        )

    return WizardStep(
        name="install_python_packages",
        description="Install Python dependencies",
        runner=runner,
        check_safe=False,
    )
