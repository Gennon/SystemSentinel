from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult


def _sudo_mkdir(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "mkdir", "-p", str(path)], capture_output=True, text=True)


def _sudo_write(path: Path, content: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "tee", str(path)], input=content, capture_output=True, text=True)


def _tty_input(prompt: str) -> str:
    """Read a line from /dev/tty so it works even when stdin is a pipe."""
    try:
        with open("/dev/tty") as tty:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            return tty.readline().rstrip("\n")
    except OSError:
        return input(prompt)


def _discover_update_source_path() -> str | None:
    """Best-effort discovery of a local update source directory.

    Prefers the nearest ancestor containing a ``.git`` directory from the
    current working directory so setup stores the checked-out repo path.
    """
    cwd = Path.cwd().resolve()
    for candidate in [cwd, *cwd.parents]:
        if (candidate / ".git").exists():
            return str(candidate)
    return None


def _prompt_yes_no(question: str, *, default: bool) -> bool:
    default_hint = "Y/n" if default else "y/N"
    while True:
        raw = _tty_input(f"\n  {question} [{default_hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("  Invalid choice. Enter 'y' or 'n'.")


def _prompt_update_source_path(default_path: str | None) -> str:
    if default_path is not None:
        print("\n  Update source path")
        print(f"  Detected repository path: {default_path}")
        entered = _tty_input("  Press Enter to accept or provide another path: ").strip()
        return entered or default_path
    while True:
        entered = _tty_input("\n  Enter update source path: ").strip()
        if entered:
            return entered
        print("  Update source path is required.")


# Default path used by the canonical wizard; tests inject a temp path.
_DEFAULT_CONFIG_PATH = Path("/etc/sentinel/config.yaml")

# Required chat fields and their user-facing descriptions (also used in prompts).
REQUIRED_CHAT_FIELDS: dict[str, str] = {
    "token": "Bot token — the secret key from your chat platform's developer portal",
    "channel_id": "Channel ID — the numeric ID of the channel the bot should post to",
}

# Safe defaults written alongside the chat config on a fresh install.
_SAFE_DEFAULTS: dict[str, Any] = {
    "updates": {
        "enabled": True,
        "schedule": "02:00",
        "reboot_if_required": False,
        "self_update": {
            "enabled": True,
            "check_interval": "00:05:00",
            "remote": "origin",
            "branch": "main",
            "reinstall": True,
        },
    },
    "monitors": {
        "collection_interval": "00:01:00",
        "retention": "30d 00:00:00",
        "cpu": {
            "enabled": True,
            "interval": "00:01:00",
            "alert_threshold_percent": 90,
            "alert_consecutive_intervals": 2,
            "alert_cooldown": "00:30:00",
        },
        "ram": {
            "enabled": True,
            "interval": "00:01:00",
            "alert_threshold_percent": 90,
            "alert_cooldown": "00:30:00",
        },
        "disk": {
            "enabled": True,
            "interval": "00:05:00",
            "alert_threshold_percent": 85,
            "alert_cooldown": "00:30:00",
        },
        "logins": {
            "enabled": True,
            "failed_login_alert_count": 5,
            "failed_login_window": "00:10:00",
            "alert_cooldown": "00:30:00",
        },
        "network": {"enabled": True, "interval": "00:01:00"},
        "connections": {
            "enabled": True,
            "repeat_alert_count": 3,
            "repeat_alert_window": "00:10:00",
            "cooldown": "01:00:00",
            "classification": {
                "attempts_per_ip": {"suspicious": 3, "likely_access_attempt": 8},
                "distinct_destination_ports": {"suspicious": 2, "likely_access_attempt": 4},
                "recurrence_over_time": {
                    "window": "24:00:00",
                    "suspicious": 3,
                    "likely_access_attempt": 7,
                },
                "protocol_port_sensitivity": {
                    "sensitive_ports": [22, 3389, 5900],
                    "weight": 2,
                },
                "score_thresholds": {"suspicious": 3, "likely_access_attempt": 6},
                "ip_enrichment": {
                    "enabled": False,
                    "enable_reverse_dns": True,
                    "enable_asn_lookup": True,
                    "enable_geoip": True,
                    "geoip_database_path": "",
                },
            },
        },
        "services": {
            "enabled": True,
            "check_interval": "00:01:00",
            "max_restart_attempts": 3,
            "journal_lines": 20,
            "critical_services": [],
        },
    },
}

# A validator callable: (field, value, token) -> error_message | None
Validator = Callable[[str, str, "str | None"], "str | None"]


def _null_validator(field: str, value: str, token: str | None = None) -> str | None:
    return None


def _validate_existing_config(data: dict[str, Any]) -> list[str]:
    """Return a list of validation error strings for an existing config dict."""
    errors: list[str] = []
    chat_adapters = data.get("chat_adapters")
    if not isinstance(chat_adapters, dict):
        errors.append("Missing 'chat_adapters' section")
        return errors
    discord = chat_adapters.get("discord")
    if not isinstance(discord, dict):
        errors.append("Missing 'chat_adapters.discord' section")
        return errors

    for field in REQUIRED_CHAT_FIELDS:
        if not discord.get(field):
            errors.append(f"Missing required field 'chat_adapters.discord.{field}'")

    return errors


def _prompt_field(field: str, description: str, token: str | None, validator: Validator) -> str:
    """Prompt the user for a single field, retrying until validation passes."""
    while True:
        print(f"\n  {description}")
        value = _tty_input(f"  Enter {field}: ").strip()
        error = validator(field, value, token)
        if error is None:
            return value
        print(f"  Invalid: {error}. Please try again.")


def configure_chat_step(
    config_path: Path = _DEFAULT_CONFIG_PATH,
    validator: Validator = _null_validator,
) -> WizardStep:
    """Return a WizardStep that configures the minimum required chat settings.

    - If no config.yaml exists: interactively prompts for all required fields,
      validates each entry, then writes the config with safe defaults.
    - If config.yaml exists: validates the required fields and reports issues
      without overwriting user changes.
    - In check-only mode: validates an existing config; fails if none exists.
    - In unattended mode: validates an existing config; fails if none exists.
    """

    def runner(ctx: WizardContext) -> WizardStepResult:
        if config_path.exists():
            raw = yaml.safe_load(config_path.read_text()) or {}
            errors = _validate_existing_config(raw)
            if not errors:
                return WizardStepResult(
                    step_name="configure_chat",
                    outcome=StepOutcome.SUCCESS,
                    message="Existing config.yaml is valid.",
                )
            # In non-interactive modes, report the validation failure
            if ctx.check_only or ctx.unattended:
                return WizardStepResult(
                    step_name="configure_chat",
                    outcome=StepOutcome.FAILURE,
                    message="Existing config.yaml has missing or invalid fields.",
                    error="; ".join(errors),
                )
            # Interactive: fall through to prompt for the missing fields

        # No config.yaml (or existing one is incomplete) — cannot proceed without interaction
        if ctx.check_only:
            return WizardStepResult(
                step_name="configure_chat",
                outcome=StepOutcome.FAILURE,
                message="No config.yaml found. Run `sentinel setup` to create one.",
            )

        if ctx.unattended:
            return WizardStepResult(
                step_name="configure_chat",
                outcome=StepOutcome.FAILURE,
                message="No config.yaml found and running in unattended mode. "
                "Create a config.yaml before using --unattended.",
            )

        # Interactive: gather required values
        print("\nChat configuration — the wizard will walk you through the required settings.")

        token: str | None = None
        discord: dict[str, Any] = {"enabled": True}

        for field, description in REQUIRED_CHAT_FIELDS.items():
            value = _prompt_field(field, description, token, validator)
            if field == "token":
                token = value
            discord[field] = value

        enable_auto_update = _prompt_yes_no("Enable automatic daemon self-update?", default=True)
        update_source_path = _prompt_update_source_path(_discover_update_source_path())

        config: dict[str, Any] = {"chat_adapters": {"discord": discord}}
        for key, val in _SAFE_DEFAULTS.items():
            config.setdefault(key, val)
        config["updates"]["self_update"]["enabled"] = enable_auto_update
        config["updates"]["self_update"]["source_path"] = update_source_path

        _sudo_mkdir(config_path.parent)
        _sudo_write(config_path, yaml.dump(config, default_flow_style=False))

        print(f"\nConfig saved to {config_path}. Edit it any time to adjust settings.")

        return WizardStepResult(
            step_name="configure_chat",
            outcome=StepOutcome.SUCCESS,
            message=f"Chat configuration written to {config_path}.",
        )

    return WizardStep(
        name="configure_chat",
        description="Configure minimum required chat settings",
        runner=runner,
        check_safe=True,
    )
