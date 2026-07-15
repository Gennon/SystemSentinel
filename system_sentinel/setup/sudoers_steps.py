from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any

import yaml

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStepResult


def required_sudoers_rules(
    *,
    config_path: Path,
    service_restart_rule: str,
    snapper_rules: tuple[str, ...],
    timeshift_rules: tuple[str, ...],
    ufw_rules: tuple[str, ...],
    nft_rules: tuple[str, ...],
) -> list[str]:
    if not config_path.exists():
        return []
    raw = yaml.safe_load(config_path.read_text()) or {}
    if not isinstance(raw, dict):
        return []

    rules: list[str] = []
    if _services_monitor_enabled(raw):
        rules.append(service_restart_rule)
    rules.extend(
        _snapshot_rules(
            config=raw,
            snapper_rules=snapper_rules,
            timeshift_rules=timeshift_rules,
        )
    )
    rules.extend(_firewall_rules(config=raw, ufw_rules=ufw_rules, nft_rules=nft_rules))
    return rules


def build_sudoers_content(rules: list[str]) -> str:
    joined_rules = "\n".join(rules)
    return (
        "# Managed by SystemSentinel setup. Do not edit manually.\n"
        "# Allows targeted privileged operations for the sentinel user.\n"
        f"{joined_rules}\n"
    )


def install_sudoers_rules_runner(
    *,
    ctx: WizardContext,
    config_path: Path,
    sudoers_install_path: Path,
    run_command_fn: Any,
    service_restart_rule: str,
    snapper_rules: tuple[str, ...],
    timeshift_rules: tuple[str, ...],
    ufw_rules: tuple[str, ...],
    nft_rules: tuple[str, ...],
) -> WizardStepResult:
    required_rules = required_sudoers_rules(
        config_path=config_path,
        service_restart_rule=service_restart_rule,
        snapper_rules=snapper_rules,
        timeshift_rules=timeshift_rules,
        ufw_rules=ufw_rules,
        nft_rules=nft_rules,
    )
    if not required_rules:
        return WizardStepResult(
            step_name="install_sudoers_rules",
            outcome=StepOutcome.SUCCESS,
            message="No sudoers rules required for enabled features.",
        )

    if ctx.check_only:
        if not sudoers_install_path.exists():
            return WizardStepResult(
                step_name="install_sudoers_rules",
                outcome=StepOutcome.FAILURE,
                message=f"Sudoers file not found at {sudoers_install_path}.",
                error="Run sentinel setup to install required sudoers rules.",
            )
        content = sudoers_install_path.read_text()
        missing = [rule for rule in required_rules if rule not in content]
        if missing:
            return WizardStepResult(
                step_name="install_sudoers_rules",
                outcome=StepOutcome.FAILURE,
                message="Sudoers file is missing required rule(s).",
                error="; ".join(missing),
            )
        return WizardStepResult(
            step_name="install_sudoers_rules",
            outcome=StepOutcome.SUCCESS,
            message="Required sudoers rules are installed.",
        )

    content = build_sudoers_content(required_rules)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            tmp_path = Path(tmp_file.name)

        assert tmp_path is not None

        validate = run_command_fn(["/usr/sbin/visudo", "-c", "-f", str(tmp_path)])
        if validate.returncode != 0:
            return WizardStepResult(
                step_name="install_sudoers_rules",
                outcome=StepOutcome.FAILURE,
                message="Generated sudoers file failed validation.",
                error=validate.stderr.strip() or validate.stdout.strip(),
            )

        mkdir = run_command_fn(["sudo", "/bin/mkdir", "-p", str(sudoers_install_path.parent)])
        if mkdir.returncode != 0:
            return WizardStepResult(
                step_name="install_sudoers_rules",
                outcome=StepOutcome.FAILURE,
                message=f"Failed to create {sudoers_install_path.parent}.",
                error=mkdir.stderr.strip() or mkdir.stdout.strip(),
            )

        copy = run_command_fn(["sudo", "/bin/cp", str(tmp_path), str(sudoers_install_path)])
        if copy.returncode != 0:
            return WizardStepResult(
                step_name="install_sudoers_rules",
                outcome=StepOutcome.FAILURE,
                message=f"Failed to install sudoers file at {sudoers_install_path}.",
                error=copy.stderr.strip() or copy.stdout.strip(),
            )

        chmod = run_command_fn(["sudo", "/bin/chmod", "440", str(sudoers_install_path)])
        if chmod.returncode != 0:
            return WizardStepResult(
                step_name="install_sudoers_rules",
                outcome=StepOutcome.FAILURE,
                message=f"Failed to set permissions on {sudoers_install_path}.",
                error=chmod.stderr.strip() or chmod.stdout.strip(),
            )

        return WizardStepResult(
            step_name="install_sudoers_rules",
            outcome=StepOutcome.SUCCESS,
            message=f"Installed sudoers rules to {sudoers_install_path}.",
        )
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _services_monitor_enabled(config: dict[str, object]) -> bool:
    monitors = config.get("monitors")
    if not isinstance(monitors, dict):
        return False
    services = monitors.get("services")
    if not isinstance(services, dict):
        return False
    return bool(services.get("enabled", True))


def _snapshot_rules(
    *,
    config: dict[str, object],
    snapper_rules: tuple[str, ...],
    timeshift_rules: tuple[str, ...],
) -> list[str]:
    updates = config.get("updates")
    if not isinstance(updates, dict):
        return []
    self_update = updates.get("self_update")
    if not isinstance(self_update, dict):
        return []
    if not bool(self_update.get("enabled", False)):
        return []
    snapshots = self_update.get("snapshots")
    snapshots_cfg = snapshots if isinstance(snapshots, dict) else {}
    backend = str(snapshots_cfg.get("backend", "auto")).strip().lower() or "auto"
    if backend in {"none", "disabled"}:
        return []
    if backend == "snapper":
        return list(snapper_rules)
    if backend == "timeshift":
        return list(timeshift_rules)
    return [*list(snapper_rules), *list(timeshift_rules)]


def _firewall_rules(
    *,
    config: dict[str, object],
    ufw_rules: tuple[str, ...],
    nft_rules: tuple[str, ...],
) -> list[str]:
    tools = config.get("tools")
    if not isinstance(tools, dict):
        return []
    firewall = tools.get("firewall")
    if not isinstance(firewall, dict):
        return []
    if not bool(firewall.get("enabled", False)):
        return []

    backend_raw = firewall.get("backend", "auto")
    backend = str(backend_raw).strip().lower()
    if backend == "ufw":
        return list(ufw_rules)
    if backend in {"nft", "nftables"}:
        return list(nft_rules)
    return [*list(ufw_rules), *list(nft_rules)]
