from __future__ import annotations

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult


def check_platform_step() -> WizardStep:
    """Return a WizardStep that validates OS and architecture."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        # TODO: implement platform detection (Linux x86_64 / arm64)
        return WizardStepResult(
            step_name="check_platform",
            outcome=StepOutcome.SUCCESS,
            message="Platform check not yet implemented.",
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
        # TODO: detect apt/dnf/pacman and install iproute2, sqlite3, curl
        return WizardStepResult(
            step_name="install_system_packages",
            outcome=StepOutcome.SUCCESS,
            message="System package installation not yet implemented.",
        )

    return WizardStep(
        name="install_system_packages",
        description="Install required system packages",
        runner=runner,
        check_safe=False,
    )


def install_python_packages_step() -> WizardStep:
    """Return a WizardStep that installs Python dependencies into a virtualenv."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        # TODO: create/detect virtualenv and pip install system-sentinel
        return WizardStepResult(
            step_name="install_python_packages",
            outcome=StepOutcome.SUCCESS,
            message="Python package installation not yet implemented.",
        )

    return WizardStep(
        name="install_python_packages",
        description="Install Python dependencies",
        runner=runner,
        check_safe=False,
    )
