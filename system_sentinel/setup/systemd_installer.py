from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import time

from system_sentinel.setup.dependency_installer import run_command
from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult

SERVICE_TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "packaging" / "sentinel.service"
SERVICE_INSTALL_PATH = Path("/etc/systemd/system/sentinel.service")

DATA_DIR = Path("/var/lib/sentinel")
CONFIG_DIR = Path("/etc/sentinel")

_POLL_INTERVAL = 1
_POLL_MAX_ATTEMPTS = 10

# Number of directory levels above the sentinel binary that constitute the install root.
# e.g. .venv/bin/sentinel → 3 levels up = install dir
_INSTALL_DIR_DEPTH = 3


def create_sentinel_user_step() -> WizardStep:
    """Return a WizardStep that creates the dedicated sentinel system user."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        check = run_command(["/usr/bin/getent", "passwd", "sentinel"])
        user_exists = check.returncode == 0

        if ctx.check_only:
            if user_exists:
                return WizardStepResult(
                    step_name="create_sentinel_user",
                    outcome=StepOutcome.SUCCESS,
                    message="User sentinel found.",
                )
            return WizardStepResult(
                step_name="create_sentinel_user",
                outcome=StepOutcome.FAILURE,
                message="User sentinel not found.",
                error="Run sentinel setup to create the user.",
            )

        if user_exists:
            return WizardStepResult(
                step_name="create_sentinel_user",
                outcome=StepOutcome.SUCCESS,
                message="User sentinel already exists.",
            )

        result = run_command(
            [
                "sudo",
                "/usr/sbin/useradd",
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "sentinel",
            ]
        )
        if result.returncode != 0:
            return WizardStepResult(
                step_name="create_sentinel_user",
                outcome=StepOutcome.FAILURE,
                message="Failed to create sentinel user.",
                error=result.stderr.strip() or result.stdout.strip(),
            )

        return WizardStepResult(
            step_name="create_sentinel_user",
            outcome=StepOutcome.SUCCESS,
            message="Created system user sentinel.",
        )

    return WizardStep(
        name="create_sentinel_user",
        description="Create dedicated sentinel system user",
        runner=runner,
        check_safe=True,
    )


# Groups that allow the sentinel user to read system logs.
# systemd-journal: read journald entries.
# adm: read /var/log/auth.log on Debian/Ubuntu systems.
_LOG_GROUPS = ("systemd-journal", "adm")


def add_sentinel_to_log_groups_step() -> WizardStep:
    """Return a WizardStep that adds sentinel to log-reading groups.

    The sentinel user needs membership of ``systemd-journal`` to query
    journald and ``adm`` (Debian/Ubuntu) to read ``/var/log/auth.log``.
    Groups that do not exist on the current system are skipped gracefully.
    """

    def runner(ctx: WizardContext) -> WizardStepResult:
        added: list[str] = []
        skipped: list[str] = []

        for group in _LOG_GROUPS:
            group_exists = run_command(["/usr/bin/getent", "group", group]).returncode == 0
            if not group_exists:
                skipped.append(group)
                continue

            already_member = run_command(["/usr/bin/id", "-Gn", "sentinel"])
            if already_member.returncode == 0 and group in already_member.stdout.split():
                skipped.append(f"{group} (already member)")
                continue

            if ctx.check_only:
                return WizardStepResult(
                    step_name="add_sentinel_to_log_groups",
                    outcome=StepOutcome.FAILURE,
                    message=f"sentinel is not a member of {group}.",
                    error="Run sentinel setup to add the user to log groups.",
                )

            result = run_command(["sudo", "/usr/sbin/usermod", "-aG", group, "sentinel"])
            if result.returncode != 0:
                return WizardStepResult(
                    step_name="add_sentinel_to_log_groups",
                    outcome=StepOutcome.FAILURE,
                    message=f"Failed to add sentinel to group {group}.",
                    error=result.stderr.strip() or result.stdout.strip(),
                )
            added.append(group)

        if ctx.check_only:
            return WizardStepResult(
                step_name="add_sentinel_to_log_groups",
                outcome=StepOutcome.SUCCESS,
                message="sentinel is a member of all required log groups.",
            )

        parts: list[str] = []
        if added:
            parts.append(f"Added to: {', '.join(added)}.")
        if skipped:
            parts.append(f"Skipped: {', '.join(skipped)}.")
        return WizardStepResult(
            step_name="add_sentinel_to_log_groups",
            outcome=StepOutcome.SUCCESS,
            message=" ".join(parts) or "No group changes needed.",
        )

    return WizardStep(
        name="add_sentinel_to_log_groups",
        description="Add sentinel user to systemd-journal and adm log groups",
        runner=runner,
        check_safe=True,
    )


def fix_install_dir_permissions_step() -> WizardStep:
    """Return a WizardStep that ensures the sentinel user can access the install directory.

    When the package is installed under a user home directory (e.g.
    ``~/.local/system-sentinel``), the ``sentinel`` system user cannot traverse
    the path because home directories are typically mode 700/750.

    This step:
    1. Adds ``o+x`` (traverse-only) to every ancestor of the install dir that
       lives inside ``/home``, so no directory listing is exposed.
    2. Adds ``o+rX`` recursively to the install dir itself so the sentinel
       executable and its supporting files are readable and executable.
    """

    def _install_dir_from_exec(exec_path: str) -> Path:
        """Derive install root from sentinel executable path."""
        p = Path(exec_path)
        for _ in range(_INSTALL_DIR_DEPTH):
            p = p.parent
        return p

    def runner(ctx: WizardContext) -> WizardStepResult:
        exec_path = shutil.which("sentinel")
        if exec_path is None:
            return WizardStepResult(
                step_name="fix_install_dir_permissions",
                outcome=StepOutcome.FAILURE,
                message="sentinel executable not found in PATH.",
                error="Ensure system-sentinel is installed: pip install -e .",
            )

        install_dir = _install_dir_from_exec(exec_path)

        # Collect ancestor directories inside /home that need o+x for traversal.
        home = Path("/home")
        ancestors_to_fix: list[Path] = []
        current = install_dir.parent
        while True:
            try:
                current.relative_to(home)
                ancestors_to_fix.append(current)
            except ValueError:
                break
            if current == home or current == current.parent:
                break
            current = current.parent

        if ctx.check_only:
            # In check-only mode just verify the binary is executable by world (o+x).
            exec_mode = Path(exec_path).stat().st_mode
            world_exec = exec_mode & 0o001
            if world_exec:
                return WizardStepResult(
                    step_name="fix_install_dir_permissions",
                    outcome=StepOutcome.SUCCESS,
                    message="Install directory permissions look correct.",
                )
            return WizardStepResult(
                step_name="fix_install_dir_permissions",
                outcome=StepOutcome.FAILURE,
                message="Install directory may not be accessible by the sentinel user.",
                error="Run sentinel setup to fix permissions.",
            )

        # Grant o+x on each ancestor inside /home (traverse only, no read).
        for ancestor in reversed(ancestors_to_fix):
            result = run_command(["sudo", "/bin/chmod", "o+x", str(ancestor)])
            if result.returncode != 0:
                return WizardStepResult(
                    step_name="fix_install_dir_permissions",
                    outcome=StepOutcome.FAILURE,
                    message=f"Failed to set traverse permission on {ancestor}.",
                    error=result.stderr.strip() or result.stdout.strip(),
                )

        # Grant o+rX recursively on the install dir so sentinel can read/execute.
        result = run_command(["sudo", "/bin/chmod", "-R", "o+rX", str(install_dir)])
        if result.returncode != 0:
            return WizardStepResult(
                step_name="fix_install_dir_permissions",
                outcome=StepOutcome.FAILURE,
                message=f"Failed to set permissions on {install_dir}.",
                error=result.stderr.strip() or result.stdout.strip(),
            )

        return WizardStepResult(
            step_name="fix_install_dir_permissions",
            outcome=StepOutcome.SUCCESS,
            message=f"Permissions set on {install_dir} and its path ancestors.",
        )

    return WizardStep(
        name="fix_install_dir_permissions",
        description="Grant sentinel user access to install directory",
        runner=runner,
        check_safe=True,
    )


def create_data_dir_step() -> WizardStep:
    """Return a WizardStep that creates /var/lib/sentinel and /etc/sentinel,
    owned by the sentinel user, so the daemon can write its database and read
    its config without elevated privileges at runtime.
    """

    def runner(ctx: WizardContext) -> WizardStepResult:
        if ctx.check_only:
            missing = [str(d) for d in (DATA_DIR, CONFIG_DIR) if not d.exists()]
            if not missing:
                return WizardStepResult(
                    step_name="create_data_dir",
                    outcome=StepOutcome.SUCCESS,
                    message=f"{DATA_DIR} and {CONFIG_DIR} exist.",
                )
            return WizardStepResult(
                step_name="create_data_dir",
                outcome=StepOutcome.FAILURE,
                message=f"Missing directories: {', '.join(missing)}.",
                error="Run sentinel setup to create them.",
            )

        for directory in (DATA_DIR, CONFIG_DIR):
            mkdir = run_command(["sudo", "/bin/mkdir", "-p", str(directory)])
            if mkdir.returncode != 0:
                return WizardStepResult(
                    step_name="create_data_dir",
                    outcome=StepOutcome.FAILURE,
                    message=f"Failed to create {directory}.",
                    error=mkdir.stderr.strip() or mkdir.stdout.strip(),
                )
            chown = run_command(["sudo", "/bin/chown", "sentinel:sentinel", str(directory)])
            if chown.returncode != 0:
                return WizardStepResult(
                    step_name="create_data_dir",
                    outcome=StepOutcome.FAILURE,
                    message=f"Failed to set ownership on {directory}.",
                    error=chown.stderr.strip() or chown.stdout.strip(),
                )

        return WizardStepResult(
            step_name="create_data_dir",
            outcome=StepOutcome.SUCCESS,
            message=f"Created {DATA_DIR} and {CONFIG_DIR}, owned by sentinel.",
        )

    return WizardStep(
        name="create_data_dir",
        description="Create /var/lib/sentinel and /etc/sentinel data directories",
        runner=runner,
        check_safe=True,
    )


def install_systemd_service_step() -> WizardStep:
    """Return a WizardStep that writes the systemd unit file."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        if ctx.check_only:
            if SERVICE_INSTALL_PATH.exists():
                return WizardStepResult(
                    step_name="install_systemd_service",
                    outcome=StepOutcome.SUCCESS,
                    message=f"Service file found at {SERVICE_INSTALL_PATH}.",
                )
            return WizardStepResult(
                step_name="install_systemd_service",
                outcome=StepOutcome.FAILURE,
                message=f"Service file not found at {SERVICE_INSTALL_PATH}.",
                error="Run sentinel setup to install the service.",
            )

        exec_path = shutil.which("sentinel")
        if exec_path is None:
            return WizardStepResult(
                step_name="install_systemd_service",
                outcome=StepOutcome.FAILURE,
                message="sentinel executable not found in PATH.",
                error="Ensure system-sentinel is installed: pip install -e .",
            )

        template = SERVICE_TEMPLATE_PATH.read_text()
        unit_content = template.replace("{exec_path}", exec_path)
        tee = subprocess.run(
            ["sudo", "tee", str(SERVICE_INSTALL_PATH)],
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

        reload = run_command(["sudo", "/usr/bin/systemctl", "daemon-reload"])
        if reload.returncode != 0:
            return WizardStepResult(
                step_name="install_systemd_service",
                outcome=StepOutcome.FAILURE,
                message="systemctl daemon-reload failed.",
                error=reload.stderr.strip(),
            )

        return WizardStepResult(
            step_name="install_systemd_service",
            outcome=StepOutcome.SUCCESS,
            message=f"Service file installed to {SERVICE_INSTALL_PATH}.",
        )

    return WizardStep(
        name="install_systemd_service",
        description="Install systemd service unit",
        runner=runner,
        check_safe=True,
    )


def enable_systemd_service_step() -> WizardStep:
    """Return a WizardStep that enables the sentinel service on boot."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        check = run_command(["/usr/bin/systemctl", "is-enabled", "sentinel"])
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

        result = run_command(["sudo", "/usr/bin/systemctl", "enable", "sentinel"])
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

    return WizardStep(
        name="enable_systemd_service",
        description="Enable sentinel service on boot",
        runner=runner,
        check_safe=True,
    )


def start_systemd_service_step() -> WizardStep:
    """Return a WizardStep that starts the sentinel service."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        check = run_command(["/usr/bin/systemctl", "is-active", "sentinel"])
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

        start = run_command(["sudo", "/usr/bin/systemctl", "start", "sentinel"])
        if start.returncode != 0:
            return WizardStepResult(
                step_name="start_systemd_service",
                outcome=StepOutcome.FAILURE,
                message="Failed to start sentinel service.",
                error=start.stderr.strip(),
            )

        for _ in range(_POLL_MAX_ATTEMPTS):
            time.sleep(_POLL_INTERVAL)
            poll = run_command(["/usr/bin/systemctl", "is-active", "sentinel"])
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

    return WizardStep(
        name="start_systemd_service",
        description="Start sentinel service",
        runner=runner,
        check_safe=True,
    )
