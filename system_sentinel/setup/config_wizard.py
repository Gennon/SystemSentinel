from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult

# Default path used by the canonical wizard; tests inject a temp path.
_DEFAULT_CONFIG_PATH = Path("/etc/sentinel/config.yaml")

# Required chat fields and their user-facing descriptions (also used in prompts).
REQUIRED_CHAT_FIELDS: dict[str, str] = {
    "provider": "Chat provider type (e.g. 'discord')",
    "token": "Bot token — the secret key from your chat platform's developer portal",
    "channel_id": "Channel ID — the numeric ID of the channel the bot should post to",
    "allowed_users": "Allowed user IDs — comma-separated list of user IDs that may interact with the bot",
}

# Safe defaults written alongside the chat config on a fresh install.
_SAFE_DEFAULTS: dict[str, Any] = {
    "updates": {
        "enabled": True,
        "schedule": "02:00",
        "reboot_if_required": False,
    },
    "monitors": {
        "cpu": {"enabled": True, "interval_seconds": 60, "alert_threshold_percent": 90},
        "ram": {"enabled": True, "interval_seconds": 60, "alert_threshold_percent": 85},
        "disk": {"enabled": True, "interval_seconds": 300, "alert_threshold_percent": 90},
        "network": {"enabled": True, "interval_seconds": 60},
    },
}

# A validator callable: (field, value, token) -> error_message | None
Validator = Callable[[str, str, "str | None"], "str | None"]


def _null_validator(field: str, value: str, token: str | None = None) -> str | None:
    return None


def _validate_existing_config(data: dict[str, Any]) -> list[str]:
    """Return a list of validation error strings for an existing config dict."""
    errors: list[str] = []
    chat = data.get("chat")
    if not isinstance(chat, dict):
        errors.append("Missing 'chat' section")
        return errors

    for field in REQUIRED_CHAT_FIELDS:
        if field == "allowed_users":
            users = chat.get("allowed_users")
            if not users:
                errors.append("'chat.allowed_users' must have at least one user ID")
        else:
            if not chat.get(field):
                errors.append(f"Missing required field 'chat.{field}'")

    return errors


def _prompt_field(field: str, description: str, token: str | None, validator: Validator) -> str:
    """Prompt the user for a single field, retrying until validation passes."""
    while True:
        print(f"\n  {description}")
        value = input(f"  Enter {field}: ").strip()
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
            if errors:
                return WizardStepResult(
                    step_name="configure_chat",
                    outcome=StepOutcome.FAILURE,
                    message="Existing config.yaml has missing or invalid fields.",
                    error="; ".join(errors),
                )
            return WizardStepResult(
                step_name="configure_chat",
                outcome=StepOutcome.SUCCESS,
                message="Existing config.yaml is valid.",
            )

        # No config.yaml yet — cannot proceed without interaction
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
        chat: dict[str, Any] = {}

        for field, description in REQUIRED_CHAT_FIELDS.items():
            value = _prompt_field(field, description, token, validator)
            if field == "token":
                token = value
            if field == "allowed_users":
                chat[field] = [u.strip() for u in value.split(",") if u.strip()]
            else:
                chat[field] = value

        config: dict[str, Any] = {"chat": chat}
        for key, val in _SAFE_DEFAULTS.items():
            config.setdefault(key, val)

        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.dump(config, default_flow_style=False))

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
