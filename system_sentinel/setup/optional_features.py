from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import sys
import termios
import tty
from typing import cast

import yaml

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult


def _tty_input(prompt: str) -> str:
    """Read a line from /dev/tty so it works even when stdin is a pipe."""
    try:
        with open("/dev/tty") as tty_file:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            return tty_file.readline().rstrip("\n")
    except OSError:
        return input(prompt)


def _tty_read_char(prompt: str) -> str:
    """Print prompt and return a single keypress without requiring Enter."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        with open("/dev/tty") as tty_file:
            fd = tty_file.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = tty_file.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return ch
    except OSError:
        return input().strip()[:1]


CONFIG_PATH = Path("/etc/sentinel/config.yaml")


def _sudo_mkdir(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "mkdir", "-p", str(path)], capture_output=True, text=True)


def _sudo_write(path: Path, content: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "tee", str(path)], input=content, capture_output=True, text=True)


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
        key="firewall",
        display_name="Declarative firewall management",
        description="Reconcile UFW/nftables rules against desired-state config",
        pip_extra=None,
        check_command=None,
    ),
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
            answer = _tty_read_char("  Enable? (y/n): ").strip().lower()
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
    "firewall": {"tools": {"firewall": {"enabled": True}}},
    "gpu": {"monitors": {"gpu": {"enabled": True}}},
    "harden": {"tools": {"harden": {"enabled": True}}},
    "snapshot": {"updates": {"self_update": {"snapshots": {"backend": "auto"}}}},
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
            _sudo_mkdir(CONFIG_PATH.parent)
            if not CONFIG_PATH.exists():
                _sudo_write(CONFIG_PATH, "{}\n")
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
        _sudo_mkdir(CONFIG_PATH.parent)
        config: dict[str, object] = {}
        if CONFIG_PATH.exists():
            config = yaml.safe_load(CONFIG_PATH.read_text()) or {}

        for key in ctx.enabled_features:
            if key in _FEATURE_CONFIG:
                config = _deep_merge(config, _FEATURE_CONFIG[key])

        _sudo_write(CONFIG_PATH, yaml.dump(config, default_flow_style=False))

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
