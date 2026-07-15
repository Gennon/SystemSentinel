from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import time

from system_sentinel.setup.dependency_installer import run_command
from system_sentinel.setup.sudoers_steps import (
    install_sudoers_rules_runner,
    required_sudoers_rules,
)
from system_sentinel.setup.systemd_service_steps import (
    enable_systemd_service_runner,
    install_systemd_service_runner,
    start_systemd_service_runner,
)
from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult

SERVICE_TEMPLATE_PATH = Path(__file__).resolve().parents[2] / "packaging" / "sentinel.service"
SERVICE_INSTALL_PATH = Path("/etc/systemd/system/sentinel.service")

DATA_DIR = Path("/var/lib/sentinel")
CONFIG_DIR = Path("/etc/sentinel")
CONFIG_PATH = CONFIG_DIR / "config.yaml"
SUDOERS_INSTALL_PATH = Path("/etc/sudoers.d/sentinel")

_POLL_INTERVAL = 1
_POLL_MAX_ATTEMPTS = 10

# Number of directory levels above the sentinel binary that constitute the install root.
# e.g. .venv/bin/sentinel → 3 levels up = install dir
_INSTALL_DIR_DEPTH = 3

_SERVICE_RESTART_RULE = "sentinel ALL=(root) NOPASSWD: /bin/systemctl restart *"
_SNAPPER_RULES = (
    "sentinel ALL=(root) NOPASSWD: /usr/bin/snapper *",
    "sentinel ALL=(root) NOPASSWD: /usr/sbin/snapper *",
    "sentinel ALL=(root) NOPASSWD: /bin/snapper *",
)
_TIMESHIFT_RULES = (
    "sentinel ALL=(root) NOPASSWD: /usr/bin/timeshift *",
    "sentinel ALL=(root) NOPASSWD: /usr/sbin/timeshift *",
    "sentinel ALL=(root) NOPASSWD: /bin/timeshift *",
)
_UFW_RULES = (
    "sentinel ALL=(root) NOPASSWD: /bin/ufw *",
    "sentinel ALL=(root) NOPASSWD: /usr/sbin/ufw *",
    "sentinel ALL=(root) NOPASSWD: /usr/bin/ufw *",
)
_NFT_RULES = (
    "sentinel ALL=(root) NOPASSWD: /bin/nft *",
    "sentinel ALL=(root) NOPASSWD: /usr/sbin/nft *",
    "sentinel ALL=(root) NOPASSWD: /usr/bin/nft *",
)


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
    3. Changes ownership of the install dir to ``sentinel:sentinel`` so the
       daemon can apply self-updates.
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

        # Make sentinel owner so it can self-update the checked-out code.
        result = run_command(["sudo", "/bin/chown", "-R", "sentinel:sentinel", str(install_dir)])
        if result.returncode != 0:
            return WizardStepResult(
                step_name="fix_install_dir_permissions",
                outcome=StepOutcome.FAILURE,
                message=f"Failed to set ownership on {install_dir}.",
                error=result.stderr.strip() or result.stdout.strip(),
            )

        return WizardStepResult(
            step_name="fix_install_dir_permissions",
            outcome=StepOutcome.SUCCESS,
            message=f"Permissions and ownership set on {install_dir} and its path ancestors.",
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


def _required_sudoers_rules() -> list[str]:
    return required_sudoers_rules(
        config_path=CONFIG_PATH,
        service_restart_rule=_SERVICE_RESTART_RULE,
        snapper_rules=_SNAPPER_RULES,
        timeshift_rules=_TIMESHIFT_RULES,
        ufw_rules=_UFW_RULES,
        nft_rules=_NFT_RULES,
    )


def install_sudoers_rules_step() -> WizardStep:
    """Return a WizardStep that installs required sudoers rules for enabled features."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        return install_sudoers_rules_runner(
            ctx=ctx,
            config_path=CONFIG_PATH,
            sudoers_install_path=SUDOERS_INSTALL_PATH,
            run_command_fn=run_command,
            service_restart_rule=_SERVICE_RESTART_RULE,
            snapper_rules=_SNAPPER_RULES,
            timeshift_rules=_TIMESHIFT_RULES,
            ufw_rules=_UFW_RULES,
            nft_rules=_NFT_RULES,
        )

    return WizardStep(
        name="install_sudoers_rules",
        description="Install required sudoers rules for enabled features",
        runner=runner,
        check_safe=True,
    )


def install_systemd_service_step() -> WizardStep:
    """Return a WizardStep that writes the systemd unit file."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        return install_systemd_service_runner(
            ctx=ctx,
            service_install_path=SERVICE_INSTALL_PATH,
            service_template_path=SERVICE_TEMPLATE_PATH,
            run_command_fn=run_command,
            which_fn=shutil.which,
            subprocess_run_fn=subprocess.run,
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
        return enable_systemd_service_runner(
            ctx=ctx,
            run_command_fn=run_command,
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
        return start_systemd_service_runner(
            ctx=ctx,
            run_command_fn=run_command,
            sleep_fn=time.sleep,
            poll_interval=_POLL_INTERVAL,
            poll_max_attempts=_POLL_MAX_ATTEMPTS,
        )

    return WizardStep(
        name="start_systemd_service",
        description="Start sentinel service",
        runner=runner,
        check_safe=True,
    )
