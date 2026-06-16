from __future__ import annotations

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult


def install_systemd_service_step() -> WizardStep:
    """Return a WizardStep that writes the systemd unit file."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        # TODO: write /etc/systemd/system/sentinel.service from packaging/sentinel.service
        return WizardStepResult(
            step_name="install_systemd_service",
            outcome=StepOutcome.SUCCESS,
            message="systemd service installation not yet implemented.",
        )

    return WizardStep(
        name="install_systemd_service",
        description="Install systemd service unit",
        runner=runner,
        check_safe=False,
    )


def enable_systemd_service_step() -> WizardStep:
    """Return a WizardStep that enables the sentinel service on boot."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        # TODO: systemctl enable sentinel
        return WizardStepResult(
            step_name="enable_systemd_service",
            outcome=StepOutcome.SUCCESS,
            message="systemd service enable not yet implemented.",
        )

    return WizardStep(
        name="enable_systemd_service",
        description="Enable sentinel service on boot",
        runner=runner,
        check_safe=False,
    )


def start_systemd_service_step() -> WizardStep:
    """Return a WizardStep that starts the sentinel service immediately."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        # TODO: systemctl start sentinel; poll for active state
        return WizardStepResult(
            step_name="start_systemd_service",
            outcome=StepOutcome.SUCCESS,
            message="systemd service start not yet implemented.",
        )

    return WizardStep(
        name="start_systemd_service",
        description="Start sentinel service",
        runner=runner,
        check_safe=False,
    )
