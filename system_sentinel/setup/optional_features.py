from __future__ import annotations

from dataclasses import dataclass
import shutil

from system_sentinel.setup.wizard import StepOutcome, WizardContext, WizardStep, WizardStepResult


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
