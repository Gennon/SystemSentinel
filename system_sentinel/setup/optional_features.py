from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys
from typing import cast

import yaml

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult

CONFIG_PATH = Path("/etc/sentinel/config.yaml")


@dataclass
class Feature:
    key: str
    display_name: str
    description: str
    pip_extra: str | None
    check_command: str | None

    def tool_present(self) -> bool:
        if self.check_command is None:
            return True
        return shutil.which(self.check_command) is not None


OPTIONAL_FEATURES: list[Feature] = [
    Feature(
        key="gpu",
        display_name="GPU monitoring",
        description="Metric collection for NVIDIA/AMD GPUs (auto-suggested if GPU detected)",
        pip_extra="gpu",
        check_command=None,
    ),
    Feature(
        key="harden",
        display_name="System hardening",
        description="CIS benchmark checks and SSH hardening",
        pip_extra=None,
        check_command=None,
    ),
    Feature(
        key="snapshot",
        display_name="Snapshot / rollback",
        description="Pre/post-update snapshots via snapper or timeshift",
        pip_extra=None,
        check_command="snapper",
    ),
    Feature(
        key="vulnscan",
        display_name="Vulnerability scanning",
        description="Periodic security audits via lynis",
        pip_extra=None,
        check_command="lynis",
    ),
    Feature(
        key="prometheus",
        display_name="Metrics export",
        description="Prometheus-compatible /metrics endpoint",
        pip_extra="prometheus",
        check_command=None,
    ),
]

_FEATURE_BY_KEY: dict[str, Feature] = {f.key: f for f in OPTIONAL_FEATURES}


def select_features_step() -> WizardStep:
    """Return a WizardStep that lets the user choose optional features."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        if ctx.check_only:
            return WizardStepResult(
                step_name="select_optional_features",
                outcome=StepOutcome.SUCCESS,
                message="Check-only mode: skipping optional feature selection.",
            )

        if ctx.unattended:
            unknown = [k for k in ctx.enabled_features if k not in _FEATURE_BY_KEY]
            if unknown:
                return WizardStepResult(
                    step_name="select_optional_features",
                    outcome=StepOutcome.FAILURE,
                    message=f"Unknown feature(s) passed via --enable: {', '.join(unknown)}",
                    error=f"Valid features: {', '.join(_FEATURE_BY_KEY)}",
                )
            return WizardStepResult(
                step_name="select_optional_features",
                outcome=StepOutcome.SUCCESS,
                message=f"Unattended: {', '.join(ctx.enabled_features) or 'no optional features selected'}.",
            )

        # Interactive per-feature prompts
        print("\nOptional features:")
        selected: list[str] = []
        for feature in OPTIONAL_FEATURES:
            status = "✓ installed" if feature.tool_present() else "not installed"
            print(f"\n  {feature.display_name} — {feature.description} [{status}]")
            answer = input("  Enable? (y/n): ").strip().lower()
            if answer == "y":
                selected.append(feature.key)

        ctx.enabled_features = selected

        return WizardStepResult(
            step_name="select_optional_features",
            outcome=StepOutcome.SUCCESS,
            message=f"Selected: {', '.join(ctx.enabled_features) or 'none'}.",
        )

    return WizardStep(
        name="select_optional_features",
        description="Select optional features to enable",
        runner=runner,
        check_safe=True,
    )


# Config keys that each feature maps to for enabling in config.yaml
_FEATURE_CONFIG: dict[str, dict[str, object]] = {
    "gpu": {"monitors": {"gpu": {"enabled": True}}},
    "harden": {"tools": {"harden": {"enabled": True}}},
    "snapshot": {"tools": {"snapshot": {"enabled": True}}},
    "vulnscan": {"tools": {"vulnscan": {"enabled": True}}},
    "prometheus": {"metrics_export": {"prometheus": {"enabled": True}}},
}


def _deep_merge(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    """Recursively merge override into base, returning the result."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(cast("dict[str, object]", result[key]), value)
        else:
            result[key] = value
    return result


def install_optional_features_step() -> WizardStep:
    """Return a WizardStep that installs pip extras and writes config.yaml."""

    def runner(ctx: WizardContext) -> WizardStepResult:
        if ctx.check_only:
            return WizardStepResult(
                step_name="install_optional_features",
                outcome=StepOutcome.SUCCESS,
                message="Check-only mode: skipping optional feature installation.",
            )

        if not ctx.enabled_features:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            if not CONFIG_PATH.exists():
                CONFIG_PATH.write_text("{}\n")
            return WizardStepResult(
                step_name="install_optional_features",
                outcome=StepOutcome.SUCCESS,
                message="No optional features selected; config.yaml unchanged.",
            )

        # Install pip extras for features that require them
        extras: list[str] = [
            extra
            for key in ctx.enabled_features
            if key in _FEATURE_BY_KEY and (extra := _FEATURE_BY_KEY[key].pip_extra) is not None
        ]
        if extras:
            package = f"system-sentinel[{','.join(extras)}]"
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", package],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return WizardStepResult(
                    step_name="install_optional_features",
                    outcome=StepOutcome.FAILURE,
                    message=f"Failed to install pip extras: {', '.join(extras)}",
                    error=result.stderr.strip(),
                )

        # Write enabled features to config.yaml
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config: dict[str, object] = {}
        if CONFIG_PATH.exists():
            config = yaml.safe_load(CONFIG_PATH.read_text()) or {}

        for key in ctx.enabled_features:
            if key in _FEATURE_CONFIG:
                config = _deep_merge(config, _FEATURE_CONFIG[key])

        CONFIG_PATH.write_text(yaml.dump(config, default_flow_style=False))

        return WizardStepResult(
            step_name="install_optional_features",
            outcome=StepOutcome.SUCCESS,
            message=f"Installed and enabled: {', '.join(ctx.enabled_features)}.",
        )

    return WizardStep(
        name="install_optional_features",
        description="Install and configure optional features",
        runner=runner,
        check_safe=False,
    )
