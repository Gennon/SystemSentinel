from __future__ import annotations

import io
from unittest.mock import patch

from system_sentinel.setup.optional_features import (
    OPTIONAL_FEATURES,
    Feature,
    select_features_step,
)
from system_sentinel.setup.wizard import (
    SetupWizard,
    StepOutcome,
    WizardContext,
)


def _run_step(ctx: WizardContext, inputs: list[str] | None = None):
    buf = io.StringIO()
    wizard = SetupWizard(steps=[select_features_step()], output=buf)
    if inputs is not None:
        with patch("builtins.input", side_effect=inputs):
            results = wizard.run(ctx)
    else:
        results = wizard.run(ctx)
    return results, buf.getvalue()


# ---------------------------------------------------------------------------
# Feature dataclass
# ---------------------------------------------------------------------------


class TestFeature:
    def test_feature_has_required_fields(self) -> None:
        f = Feature(
            key="gpu",
            display_name="GPU monitoring",
            description="Metric collection for NVIDIA/AMD GPUs",
            pip_extra="gpu",
            check_command=None,
        )
        assert f.key == "gpu"
        assert f.display_name == "GPU monitoring"

    def test_feature_tool_present_when_command_found(self) -> None:
        f = Feature(
            key="lynis",
            display_name="Vulnerability scanning",
            description="Periodic security audits via lynis",
            pip_extra=None,
            check_command="lynis",
        )
        with patch(
            "system_sentinel.setup.optional_features.shutil.which", return_value="/usr/bin/lynis"
        ):
            assert f.tool_present() is True

    def test_feature_tool_absent_when_command_not_found(self) -> None:
        f = Feature(
            key="lynis",
            display_name="Vulnerability scanning",
            description="Periodic security audits via lynis",
            pip_extra=None,
            check_command="lynis",
        )
        with patch("system_sentinel.setup.optional_features.shutil.which", return_value=None):
            assert f.tool_present() is False

    def test_feature_without_check_command_is_always_present(self) -> None:
        f = Feature(
            key="gpu",
            display_name="GPU monitoring",
            description="GPU metrics",
            pip_extra="gpu",
            check_command=None,
        )
        assert f.tool_present() is True


# ---------------------------------------------------------------------------
# OPTIONAL_FEATURES registry
# ---------------------------------------------------------------------------


class TestOptionalFeaturesRegistry:
    def test_all_expected_features_present(self) -> None:
        keys = {f.key for f in OPTIONAL_FEATURES}
        assert "gpu" in keys
        assert "harden" in keys
        assert "snapshot" in keys
        assert "vulnscan" in keys
        assert "prometheus" in keys

    def test_feature_keys_are_unique(self) -> None:
        keys = [f.key for f in OPTIONAL_FEATURES]
        assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# select_features_step — unattended mode
# ---------------------------------------------------------------------------


class TestSelectFeaturesStepUnattended:
    def test_step_is_check_safe(self) -> None:
        assert select_features_step().check_safe is True

    def test_unattended_no_flags_selects_nothing(self) -> None:
        ctx = WizardContext(unattended=True)
        results, _ = _run_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert ctx.enabled_features == []

    def test_unattended_with_enable_flag_selects_features(self) -> None:
        ctx = WizardContext(unattended=True, enabled_features=["gpu", "prometheus"])
        results, _ = _run_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert "gpu" in ctx.enabled_features
        assert "prometheus" in ctx.enabled_features

    def test_unattended_unknown_feature_returns_failure(self) -> None:
        ctx = WizardContext(unattended=True, enabled_features=["nonexistent"])
        results, _ = _run_step(ctx)

        assert results[0].outcome == StepOutcome.FAILURE
        assert "nonexistent" in results[0].message


# ---------------------------------------------------------------------------
# select_features_step — interactive mode
# ---------------------------------------------------------------------------


class TestSelectFeaturesStepInteractive:
    def _all_no(self) -> list[str]:
        """Return 'n' for every feature prompt."""
        return ["n"] * len(OPTIONAL_FEATURES)

    def _all_yes(self) -> list[str]:
        """Return 'y' for every feature prompt."""
        return ["y"] * len(OPTIONAL_FEATURES)

    def test_all_no_selects_nothing(self) -> None:
        ctx = WizardContext()
        results, _ = _run_step(ctx, inputs=self._all_no())

        assert results[0].outcome == StepOutcome.SUCCESS
        assert ctx.enabled_features == []

    def test_all_yes_selects_all_features(self) -> None:
        ctx = WizardContext()
        results, _ = _run_step(ctx, inputs=self._all_yes())

        assert results[0].outcome == StepOutcome.SUCCESS
        assert len(ctx.enabled_features) == len(OPTIONAL_FEATURES)

    def test_yes_to_first_selects_only_first(self) -> None:
        ctx = WizardContext()
        inputs = ["y"] + ["n"] * (len(OPTIONAL_FEATURES) - 1)
        results, _ = _run_step(ctx, inputs=inputs)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert ctx.enabled_features == [OPTIONAL_FEATURES[0].key]

    def test_yes_to_last_selects_only_last(self) -> None:
        ctx = WizardContext()
        inputs = ["n"] * (len(OPTIONAL_FEATURES) - 1) + ["y"]
        results, _ = _run_step(ctx, inputs=inputs)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert ctx.enabled_features == [OPTIONAL_FEATURES[-1].key]

    def test_check_only_skips_prompt_and_succeeds(self) -> None:
        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_all_features_listed_in_output(self, capsys) -> None:
        ctx = WizardContext()
        _run_step(ctx, inputs=self._all_no())

        captured = capsys.readouterr().out
        for feature in OPTIONAL_FEATURES:
            assert feature.display_name in captured
