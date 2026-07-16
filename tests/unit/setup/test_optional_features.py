from __future__ import annotations

import io
import subprocess
from typing import TYPE_CHECKING
from unittest.mock import patch

import yaml

if TYPE_CHECKING:
    from pathlib import Path

from system_sentinel.setup.optional_features import (
    OPTIONAL_FEATURES,
    Feature,
    install_optional_features_step,
    select_features_step,
)
from system_sentinel.setup.wizard import (
    SetupWizard,
    StepOutcome,
    WizardContext,
)


def _make_sudo_run(returncode: int = 0):
    """Return a subprocess.run side_effect that simulates sudo tee writing files."""

    def _side_effect(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "tee" in cmd:
            path = cmd[-1]
            content = kwargs.get("input", "")
            import pathlib

            pathlib.Path(path).write_text(str(content))
        return subprocess.CompletedProcess(args=cmd, returncode=returncode, stdout="", stderr="")

    return _side_effect


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
        assert "firewall" in keys
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


# ---------------------------------------------------------------------------
# install_optional_features_step
# ---------------------------------------------------------------------------


def _run_install_step(ctx: WizardContext):
    buf = io.StringIO()
    wizard = SetupWizard(steps=[install_optional_features_step()], output=buf)
    results = wizard.run(ctx)
    return results, buf.getvalue()


class TestInstallOptionalFeaturesStep:
    def test_step_is_not_check_safe(self) -> None:
        assert install_optional_features_step().check_safe is False

    def test_no_features_selected_succeeds_without_installing(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(enabled_features=[])
        with (
            patch("system_sentinel.setup.optional_features.CONFIG_PATH", config_path),
            patch(
                "system_sentinel.setup.optional_features.subprocess.run",
                side_effect=_make_sudo_run(),
            ),
        ):
            results, _ = _run_install_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_feature_with_pip_extra_installs_it(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(enabled_features=["gpu"])

        with (
            patch(
                "system_sentinel.setup.optional_features.CONFIG_PATH",
                config_path,
            ),
            patch(
                "system_sentinel.setup.optional_features.subprocess.run",
                side_effect=_make_sudo_run(),
            ) as mock_run,
        ):
            results, _ = _run_install_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("gpu" in c for c in calls)

    def test_pip_install_failure_returns_failure(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(enabled_features=["gpu"])

        with (
            patch(
                "system_sentinel.setup.optional_features.CONFIG_PATH",
                config_path,
            ),
            patch(
                "system_sentinel.setup.optional_features.subprocess.run",
                side_effect=_make_sudo_run(returncode=1),
            ),
        ):
            results, _ = _run_install_step(ctx)

        assert results[0].outcome == StepOutcome.FAILURE
        assert results[0].error is not None

    def test_feature_without_pip_extra_skips_pip(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(enabled_features=["harden"])

        with (
            patch(
                "system_sentinel.setup.optional_features.CONFIG_PATH",
                config_path,
            ),
            patch(
                "system_sentinel.setup.optional_features.subprocess.run",
                side_effect=_make_sudo_run(),
            ) as mock_run,
        ):
            results, _ = _run_install_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        # Only sudo mkdir and sudo tee should run — no pip install
        for call in mock_run.call_args_list:
            cmd = call.args[0] if call.args else call.kwargs.get("cmd", [])
            assert not ("-m" in cmd and "pip" in cmd)

    def test_writes_config_yaml_with_selected_features(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(enabled_features=["gpu", "prometheus"])

        with (
            patch(
                "system_sentinel.setup.optional_features.CONFIG_PATH",
                config_path,
            ),
            patch(
                "system_sentinel.setup.optional_features.subprocess.run",
                side_effect=_make_sudo_run(),
            ),
        ):
            results, _ = _run_install_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert config_path.exists()
        content = config_path.read_text()
        assert "gpu" in content
        assert "prometheus" in content

    def test_config_yaml_created_even_with_no_pip_features(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(enabled_features=["harden"])

        with (
            patch(
                "system_sentinel.setup.optional_features.CONFIG_PATH",
                config_path,
            ),
            patch(
                "system_sentinel.setup.optional_features.subprocess.run",
                side_effect=_make_sudo_run(),
            ),
        ):
            results, _ = _run_install_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert config_path.exists()
        config = yaml.safe_load(config_path.read_text())
        assert config["tools"]["hardening"]["enabled"] is True
        assert config["tools"]["hardening"]["benchmarks"]["cis_level_1"] is True

    def test_snapshot_feature_writes_self_update_snapshot_backend(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(enabled_features=["snapshot"])

        with (
            patch(
                "system_sentinel.setup.optional_features.CONFIG_PATH",
                config_path,
            ),
            patch(
                "system_sentinel.setup.optional_features.subprocess.run",
                side_effect=_make_sudo_run(),
            ),
        ):
            results, _ = _run_install_step(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        config = yaml.safe_load(config_path.read_text())
        assert config["updates"]["self_update"]["snapshots"]["backend"] == "auto"

    def test_check_only_skips_install_and_write(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext(check_only=True, enabled_features=["gpu"])

        with (
            patch(
                "system_sentinel.setup.optional_features.CONFIG_PATH",
                config_path,
            ),
            patch("system_sentinel.setup.optional_features.subprocess.run") as mock_run,
        ):
            results, _ = _run_install_step(ctx)

        # check_safe=False so wizard marks as SKIPPED in check-only mode
        assert results[0].outcome == StepOutcome.SKIPPED
        mock_run.assert_not_called()
        assert not config_path.exists()
