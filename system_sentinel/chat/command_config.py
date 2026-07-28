"""AI-driven configuration update command (US-044).

This module handles the ``!config`` chat command, which lets admins update
``config.yaml`` settings via natural-language requests interpreted by the LLM.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import json
import os
import re
import tempfile
from typing import TYPE_CHECKING, Any
import uuid

import yaml

from system_sentinel.core.time_config import parse_duration_hhmmss

if TYPE_CHECKING:
    from pathlib import Path

    from system_sentinel.core.context import LLMClient

# ---------------------------------------------------------------------------
# Settable-key schema
# ---------------------------------------------------------------------------

_CONFIRMATION_TTL_SECONDS = 300


@dataclass(frozen=True)
class ConfigKeySchema:
    path: str
    description: str
    value_type: str  # "number" | "integer" | "string" | "boolean"
    keywords: list[str] = field(default_factory=list)
    min_value: float | None = None
    max_value: float | None = None


SETTABLE_CONFIG_KEYS: list[ConfigKeySchema] = [
    # ---- CPU ----------------------------------------------------------------
    ConfigKeySchema(
        path="monitors.cpu.enabled",
        description="Enable or disable CPU monitoring",
        value_type="boolean",
        keywords=["cpu", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.cpu.alert_threshold_percent",
        description="CPU usage alert threshold percentage",
        value_type="number",
        keywords=["cpu", "processor", "alert", "threshold"],
        min_value=0.0,
        max_value=100.0,
    ),
    ConfigKeySchema(
        path="monitors.cpu.alert_consecutive_intervals",
        description="Consecutive intervals above threshold before a CPU alert fires",
        value_type="integer",
        keywords=["cpu", "consecutive", "intervals"],
        min_value=1.0,
    ),
    ConfigKeySchema(
        path="monitors.cpu.alert_cooldown",
        description="Minimum time between CPU alerts (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["cpu", "alert", "cooldown"],
    ),
    # ---- RAM ----------------------------------------------------------------
    ConfigKeySchema(
        path="monitors.ram.enabled",
        description="Enable or disable RAM monitoring",
        value_type="boolean",
        keywords=["ram", "memory", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.ram.alert_threshold_percent",
        description="RAM usage alert threshold percentage",
        value_type="number",
        keywords=["ram", "memory", "alert", "threshold"],
        min_value=0.0,
        max_value=100.0,
    ),
    ConfigKeySchema(
        path="monitors.ram.alert_cooldown",
        description="Minimum time between RAM alerts (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["ram", "memory", "alert", "cooldown"],
    ),
    # ---- Disk ---------------------------------------------------------------
    ConfigKeySchema(
        path="monitors.disk.enabled",
        description="Enable or disable disk monitoring",
        value_type="boolean",
        keywords=["disk", "storage", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.disk.alert_threshold_percent",
        description="Disk usage alert threshold percentage",
        value_type="number",
        keywords=["disk", "storage", "alert", "threshold"],
        min_value=0.0,
        max_value=100.0,
    ),
    ConfigKeySchema(
        path="monitors.disk.alert_cooldown",
        description="Minimum time between disk alerts (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["disk", "storage", "alert", "cooldown"],
    ),
    # ---- Network ------------------------------------------------------------
    ConfigKeySchema(
        path="monitors.network.enabled",
        description="Enable or disable network monitoring",
        value_type="boolean",
        keywords=["network", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.network.alert_threshold_bytes_sent",
        description="Outbound network alert threshold in bytes",
        value_type="integer",
        keywords=["network", "sent", "outbound", "alert", "threshold", "bytes"],
        min_value=0.0,
    ),
    ConfigKeySchema(
        path="monitors.network.alert_threshold_bytes_recv",
        description="Inbound network alert threshold in bytes",
        value_type="integer",
        keywords=["network", "recv", "receive", "inbound", "alert", "threshold", "bytes"],
        min_value=0.0,
    ),
    ConfigKeySchema(
        path="monitors.network.alert_cooldown",
        description="Minimum time between network alerts (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["network", "alert", "cooldown"],
    ),
    # ---- GPU ----------------------------------------------------------------
    ConfigKeySchema(
        path="monitors.gpu.enabled",
        description="Enable or disable GPU monitoring",
        value_type="boolean",
        keywords=["gpu", "graphics", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.gpu.alert_threshold_utilization_percent",
        description="GPU utilization alert threshold percentage",
        value_type="number",
        keywords=["gpu", "graphics", "utilization", "alert", "threshold"],
        min_value=0.0,
        max_value=100.0,
    ),
    ConfigKeySchema(
        path="monitors.gpu.alert_threshold_temperature_c",
        description="GPU temperature alert threshold in degrees Celsius",
        value_type="number",
        keywords=["gpu", "graphics", "temperature", "heat", "alert", "threshold"],
        min_value=0.0,
        max_value=150.0,
    ),
    ConfigKeySchema(
        path="monitors.gpu.alert_cooldown",
        description="Minimum time between GPU alerts (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["gpu", "alert", "cooldown"],
    ),
    # ---- Services -----------------------------------------------------------
    ConfigKeySchema(
        path="monitors.services.enabled",
        description="Enable or disable service availability monitoring",
        value_type="boolean",
        keywords=["services", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.services.check_interval",
        description="How often to check critical services (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["services", "check", "interval"],
    ),
    # ---- Logins -------------------------------------------------------------
    ConfigKeySchema(
        path="monitors.logins.enabled",
        description="Enable or disable login monitoring",
        value_type="boolean",
        keywords=["logins", "login", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.logins.failed_login_alert_count",
        description="Number of failed logins within the window before an alert fires",
        value_type="integer",
        keywords=["logins", "failed", "alert", "count", "attempts"],
        min_value=1.0,
    ),
    ConfigKeySchema(
        path="monitors.logins.failed_login_window",
        description="Time window for counting failed logins (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["logins", "failed", "window"],
    ),
    ConfigKeySchema(
        path="monitors.logins.alert_cooldown",
        description="Minimum time between login alerts (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["logins", "alert", "cooldown"],
    ),
    ConfigKeySchema(
        path="monitors.logins.anomaly_detection.brute_force_enabled",
        description="Enable brute-force login anomaly detection",
        value_type="boolean",
        keywords=["logins", "anomaly", "brute", "force", "enabled"],
    ),
    ConfigKeySchema(
        path="monitors.logins.anomaly_detection.off_hours_enabled",
        description="Enable off-hours login anomaly detection",
        value_type="boolean",
        keywords=["logins", "anomaly", "off", "hours", "enabled"],
    ),
    ConfigKeySchema(
        path="monitors.logins.anomaly_detection.new_user_enabled",
        description="Enable new-user login anomaly detection",
        value_type="boolean",
        keywords=["logins", "anomaly", "new", "user", "enabled"],
    ),
    ConfigKeySchema(
        path="monitors.logins.anomaly_detection.impossible_travel_enabled",
        description="Enable impossible-travel login anomaly detection",
        value_type="boolean",
        keywords=["logins", "anomaly", "impossible", "travel", "enabled"],
    ),
    # ---- Connections --------------------------------------------------------
    ConfigKeySchema(
        path="monitors.connections.enabled",
        description="Enable or disable network connection monitoring",
        value_type="boolean",
        keywords=["connections", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.connections.repeat_alert_count",
        description="Number of repeated connections before alerting",
        value_type="integer",
        keywords=["connections", "repeat", "alert", "count"],
        min_value=1.0,
    ),
    ConfigKeySchema(
        path="monitors.connections.repeat_alert_window",
        description="Time window for counting repeated connections (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["connections", "repeat", "alert", "window"],
    ),
    ConfigKeySchema(
        path="monitors.connections.cooldown",
        description="Minimum time between connection alerts (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["connections", "alert", "cooldown"],
    ),
    # ---- Old files ----------------------------------------------------------
    ConfigKeySchema(
        path="monitors.old_files.enabled",
        description="Enable or disable old-files monitoring",
        value_type="boolean",
        keywords=["old_files", "old", "files", "enabled", "disable", "enable"],
    ),
    ConfigKeySchema(
        path="monitors.old_files.scan_interval",
        description="How often to scan for old files (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["old_files", "scan", "interval"],
    ),
    ConfigKeySchema(
        path="monitors.old_files.age_threshold",
        description="Age above which a file is considered old (HH:MM:SS or Xd HH:MM:SS)",
        value_type="duration",
        keywords=["old_files", "age", "threshold"],
    ),
    # ---- Directory changes --------------------------------------------------
    ConfigKeySchema(
        path="monitors.directory_changes.enabled",
        description="Enable or disable directory-change monitoring",
        value_type="boolean",
        keywords=["directory_changes", "directory", "changes", "enabled", "disable", "enable"],
    ),
    # ---- File integrity -----------------------------------------------------
    ConfigKeySchema(
        path="monitors.file_integrity.enabled",
        description="Enable or disable file-integrity monitoring",
        value_type="boolean",
        keywords=["file_integrity", "file", "integrity", "enabled", "disable", "enable"],
    ),
]

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfigChangeProposal:
    key_path: str
    old_value: Any
    new_value: Any
    description: str


@dataclass(frozen=True)
class ConfigClarificationNeeded:
    question: str


ConfigInterpretResult = ConfigChangeProposal | ConfigClarificationNeeded


@dataclass(frozen=True)
class PendingConfigChange:
    key_path: str
    old_value: Any
    new_value: Any
    original_request: str
    description: str
    requested_at: datetime
    expires_at: datetime
    request_id: str

    @classmethod
    def from_proposal(cls, proposal: ConfigChangeProposal, request: str) -> PendingConfigChange:
        now = datetime.now(UTC)
        return cls(
            key_path=proposal.key_path,
            old_value=proposal.old_value,
            new_value=proposal.new_value,
            original_request=request,
            description=proposal.description,
            requested_at=now,
            expires_at=now + timedelta(seconds=_CONFIRMATION_TTL_SECONDS),
            request_id=uuid.uuid4().hex[:8],
        )


# ---------------------------------------------------------------------------
# LLM interpretation
# ---------------------------------------------------------------------------


def _build_schema_description() -> str:
    lines = [
        "Settable configuration keys:",
        "(Duration values use HH:MM:SS format, e.g. '01:00:00' for 1 hour, '00:05:00' for 5 minutes,"
        " or '<days>d HH:MM:SS' for multi-day durations like '7d 00:00:00'.)",
    ]
    for key in SETTABLE_CONFIG_KEYS:
        constraints = ""
        if key.min_value is not None and key.max_value is not None:
            constraints = f" (range: {key.min_value}-{key.max_value})"
        elif key.min_value is not None:
            constraints = f" (min: {key.min_value})"
        lines.append(f"  {key.path}  [{key.value_type}]{constraints} -- {key.description}")
    return "\n".join(lines)


async def interpret_config_request(
    llm_client: LLMClient,
    request: str,
    current_config: dict[str, Any],
) -> ConfigInterpretResult:
    """Ask the LLM to map a natural-language request to a config key + value."""
    schema_desc = _build_schema_description()
    system_prompt = (
        "You are a configuration assistant for SystemSentinel, a Linux monitoring daemon.\n"
        "Given a natural-language config change request, respond ONLY with a JSON object.\n\n"
        f"{schema_desc}\n\n"
        'If the request clearly maps to one key, respond: {"action":"change","key_path":"<path>","new_value":<value>}\n'
        'For duration keys the new_value must be a string in HH:MM:SS format (e.g. "00:30:00" for 30 minutes).\n\n'
        'If the request is ambiguous or maps to no known key, respond: {"action":"clarify","question":"<question>"}\n\n'
        "Respond with ONLY the JSON -- no explanations, no markdown."
    )

    response = await llm_client.complete(
        prompt=request,
        system_prompt=system_prompt,
        timeout_seconds=15.0,
    )
    return _parse_llm_response(response.text, current_config)


def _parse_llm_response(
    text: str,
    current_config: dict[str, Any],
) -> ConfigInterpretResult:
    json_text = _extract_json(text)
    try:
        data = json.loads(json_text)
    except (json.JSONDecodeError, ValueError):
        return ConfigClarificationNeeded(
            question=(
                "I couldn't understand that config change request. "
                "Try something like: 'set CPU alert threshold to 90'"
            )
        )

    if not isinstance(data, dict):
        return ConfigClarificationNeeded(
            question="Could you clarify which config setting to change?"
        )

    action = data.get("action")

    if action == "clarify":
        question = data.get("question", "Could you clarify which config setting to change?")
        return ConfigClarificationNeeded(question=str(question))

    if action == "change":
        key_path = data.get("key_path")
        new_value = data.get("new_value")

        if not isinstance(key_path, str):
            return ConfigClarificationNeeded(
                question="Which configuration key do you want to change?"
            )

        schema = _find_schema_key(key_path)
        if schema is None:
            return ConfigClarificationNeeded(
                question=f"I don't know the config key '{key_path}'. Could you clarify?"
            )

        old_value = get_nested_value(current_config, key_path)

        coerced, error = _coerce_and_validate(new_value, schema)
        if error is not None:
            return ConfigClarificationNeeded(question=error)

        return ConfigChangeProposal(
            key_path=key_path,
            old_value=old_value,
            new_value=coerced,
            description=schema.description,
        )

    return ConfigClarificationNeeded(question="Could you clarify which config setting to change?")


def _extract_json(text: str) -> str:
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return match.group(0)
    return text.strip()


def _find_schema_key(path: str) -> ConfigKeySchema | None:
    for key in SETTABLE_CONFIG_KEYS:
        if key.path == path:
            return key
    return None


def _coerce_and_validate(
    value: Any,
    schema: ConfigKeySchema,
) -> tuple[Any, str | None]:
    """Coerce value to the expected type and validate constraints.

    Returns ``(coerced_value, None)`` on success or ``(None, error_message)`` on failure.
    """
    try:
        coerced: Any
        if schema.value_type == "duration":
            if not isinstance(value, str):
                return None, "Duration must be a string in HH:MM:SS or Xd HH:MM:SS format."
            parsed = parse_duration_hhmmss(value)
            if parsed is None:
                return (
                    None,
                    f"'{value}' is not a valid duration. Use HH:MM:SS format, e.g. '01:30:00' for 90 minutes.",
                )
            coerced = value
        elif schema.value_type == "integer":
            coerced = int(value)
        elif schema.value_type == "number":
            coerced = float(value)
        elif schema.value_type == "boolean":
            if isinstance(value, bool):
                coerced = value
            elif isinstance(value, str):
                coerced = value.lower() in {"true", "yes", "1"}
            else:
                coerced = bool(value)
        else:
            coerced = str(value)
    except (ValueError, TypeError):
        return None, f"Could not convert '{value}' to {schema.value_type}."

    if (
        schema.min_value is not None
        and schema.value_type not in {"boolean", "duration"}
        and float(coerced) < schema.min_value
    ):
        return None, f"Value must be at least {schema.min_value}."
    if (
        schema.max_value is not None
        and schema.value_type not in {"boolean", "duration"}
        and float(coerced) > schema.max_value
    ):
        return None, f"Value must be at most {schema.max_value}."

    return coerced, None


# ---------------------------------------------------------------------------
# Config file helpers
# ---------------------------------------------------------------------------


def get_nested_value(config: dict[str, Any], key_path: str) -> Any:
    """Return the value at *key_path* (dot-separated) or ``None`` if missing."""
    parts = key_path.split(".")
    current: Any = config
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def set_nested_value(config: dict[str, Any], key_path: str, value: Any) -> None:
    """Set the value at *key_path* (dot-separated), creating intermediate dicts as needed."""
    parts = key_path.split(".")
    current = config
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


def check_config_writable(config_path: Path) -> str | None:
    """Return an error message if *config_path* cannot be written, else ``None``."""
    if not config_path.exists():
        return f"Config file not found: {config_path}"
    if not os.access(config_path, os.W_OK):
        return (
            f"Permission denied: cannot write to {config_path}. "
            "The daemon process does not have write access to the config file."
        )
    return None


def apply_config_change(
    config_path: Path,
    key_path: str,
    new_value: Any,
) -> Any:
    """Atomically write *new_value* at *key_path* in *config_path*.

    Uses a temp file + rename so the config is never left in a partial state.
    Returns the previous value (or ``None`` if the key was absent).
    Raises ``PermissionError`` if the file is not writable.
    """
    raw: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
    old_value = get_nested_value(raw, key_path)
    set_nested_value(raw, key_path, new_value)
    new_content = yaml.safe_dump(raw, default_flow_style=False, allow_unicode=True)

    # Write atomically: temp file in the same directory → rename
    config_dir = config_path.parent
    fd, tmp_path = tempfile.mkstemp(dir=config_dir, prefix=".sentinel-config-", suffix=".yaml.tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(new_content)
        os.replace(tmp_path, config_path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

    return old_value


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_config_proposal(proposal: ConfigChangeProposal) -> str:
    old = repr(proposal.old_value) if proposal.old_value is not None else "not set"
    return (
        f"**Proposed config change**\n"
        f"Key: `{proposal.key_path}`\n"
        f"Description: {proposal.description}\n"
        f"Current value: `{old}`\n"
        f"New value: `{proposal.new_value!r}`\n\n"
        f"React with \u2705 within {_CONFIRMATION_TTL_SECONDS // 60} minutes to apply."
    )
