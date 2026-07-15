from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStepResult


def install_systemd_service_runner(
    *,
    ctx: WizardContext,
    service_install_path: Path,
    service_template_path: Path,
    run_command_fn: Any,
    which_fn: Any,
    subprocess_run_fn: Any,
) -> WizardStepResult:
    if ctx.check_only:
        if service_install_path.exists():
            return WizardStepResult(
                step_name="install_systemd_service",
                outcome=StepOutcome.SUCCESS,
                message=f"Service file found at {service_install_path}.",
            )
        return WizardStepResult(
            step_name="install_systemd_service",
            outcome=StepOutcome.FAILURE,
            message=f"Service file not found at {service_install_path}.",
            error="Run sentinel setup to install the service.",
        )

    exec_path = which_fn("sentinel")
    if exec_path is None:
        return WizardStepResult(
            step_name="install_systemd_service",
            outcome=StepOutcome.FAILURE,
            message="sentinel executable not found in PATH.",
            error="Ensure system-sentinel is installed: pip install -e .",
        )

    template = service_template_path.read_text()
    unit_content = template.replace("{exec_path}", exec_path)
    tee = subprocess_run_fn(
        ["sudo", "tee", str(service_install_path)],
        input=unit_content,
        capture_output=True,
        text=True,
    )
    if tee.returncode != 0:
        return WizardStepResult(
            step_name="install_systemd_service",
            outcome=StepOutcome.FAILURE,
            message="Failed to write service file.",
            error=tee.stderr.strip(),
        )

    reload_result = run_command_fn(["sudo", "/usr/bin/systemctl", "daemon-reload"])
    if reload_result.returncode != 0:
        return WizardStepResult(
            step_name="install_systemd_service",
            outcome=StepOutcome.FAILURE,
            message="systemctl daemon-reload failed.",
            error=reload_result.stderr.strip(),
        )

    return WizardStepResult(
        step_name="install_systemd_service",
        outcome=StepOutcome.SUCCESS,
        message=f"Service file installed to {service_install_path}.",
    )


def enable_systemd_service_runner(
    *,
    ctx: WizardContext,
    run_command_fn: Any,
) -> WizardStepResult:
    check = run_command_fn(["/usr/bin/systemctl", "is-enabled", "sentinel"])
    is_enabled = check.returncode == 0

    if ctx.check_only:
        if is_enabled:
            return WizardStepResult(
                step_name="enable_systemd_service",
                outcome=StepOutcome.SUCCESS,
                message="Service sentinel is enabled.",
            )
        return WizardStepResult(
            step_name="enable_systemd_service",
            outcome=StepOutcome.FAILURE,
            message="Service sentinel is not enabled.",
            error="Run sentinel setup to enable the service.",
        )

    if is_enabled:
        return WizardStepResult(
            step_name="enable_systemd_service",
            outcome=StepOutcome.SUCCESS,
            message="Service sentinel already enabled.",
        )

    result = run_command_fn(["sudo", "/usr/bin/systemctl", "enable", "sentinel"])
    if result.returncode != 0:
        return WizardStepResult(
            step_name="enable_systemd_service",
            outcome=StepOutcome.FAILURE,
            message="Failed to enable sentinel service.",
            error=result.stderr.strip(),
        )

    return WizardStepResult(
        step_name="enable_systemd_service",
        outcome=StepOutcome.SUCCESS,
        message="Service sentinel enabled.",
    )


def start_systemd_service_runner(
    *,
    ctx: WizardContext,
    run_command_fn: Any,
    sleep_fn: Any,
    poll_interval: int,
    poll_max_attempts: int,
) -> WizardStepResult:
    check = run_command_fn(["/usr/bin/systemctl", "is-active", "sentinel"])
    is_active = check.returncode == 0

    if ctx.check_only:
        if is_active:
            return WizardStepResult(
                step_name="start_systemd_service",
                outcome=StepOutcome.SUCCESS,
                message="Service sentinel is active.",
            )
        return WizardStepResult(
            step_name="start_systemd_service",
            outcome=StepOutcome.FAILURE,
            message="Service sentinel is not active.",
            error="Run sentinel setup to start the service.",
        )

    if is_active:
        return WizardStepResult(
            step_name="start_systemd_service",
            outcome=StepOutcome.SUCCESS,
            message="Service sentinel already active.",
        )

    start = run_command_fn(["sudo", "/usr/bin/systemctl", "start", "sentinel"])
    if start.returncode != 0:
        return WizardStepResult(
            step_name="start_systemd_service",
            outcome=StepOutcome.FAILURE,
            message="Failed to start sentinel service.",
            error=start.stderr.strip(),
        )

    for _ in range(poll_max_attempts):
        sleep_fn(poll_interval)
        poll = run_command_fn(["/usr/bin/systemctl", "is-active", "sentinel"])
        if poll.returncode == 0:
            return WizardStepResult(
                step_name="start_systemd_service",
                outcome=StepOutcome.SUCCESS,
                message="Service sentinel started and active.",
            )

    return WizardStepResult(
        step_name="start_systemd_service",
        outcome=StepOutcome.FAILURE,
        message="Service sentinel timed out waiting to become active.",
        error="Check logs with: journalctl -u sentinel -n 50",
    )
