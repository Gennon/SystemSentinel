from __future__ import annotations

import io
import pathlib
from pathlib import Path
import subprocess
from unittest.mock import patch

import yaml

from system_sentinel.setup.config_wizard import (
    REQUIRED_CHAT_FIELDS,
    configure_chat_step,
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
            content = kwargs.get("input", "")
            pathlib.Path(cmd[-1]).write_text(str(content))
        return subprocess.CompletedProcess(args=cmd, returncode=returncode, stdout="", stderr="")

    return _side_effect


def _run_step(
    ctx: WizardContext,
    config_path: Path,
    inputs: list[str] | None = None,
    validator_returns: dict[str, str | None] | None = None,
):
    """Run configure_chat_step and return (results, buf_output)."""

    def mock_validator(field: str, value: str, token: str | None = None) -> str | None:
        if validator_returns is None:
            return None
        return validator_returns.get(field)

    buf = io.StringIO()
    step = configure_chat_step(config_path=config_path, validator=mock_validator)
    wizard = SetupWizard(steps=[step], output=buf)

    with patch(
        "system_sentinel.setup.config_wizard.subprocess.run",
        side_effect=_make_sudo_run(),
    ):
        if inputs is not None:
            with patch("builtins.input", side_effect=inputs):
                results = wizard.run(ctx)
        else:
            results = wizard.run(ctx)

    return results, buf.getvalue()


# ---------------------------------------------------------------------------
# REQUIRED_CHAT_FIELDS
# ---------------------------------------------------------------------------


class TestRequiredChatFields:
    def test_required_fields_include_token(self) -> None:
        assert "token" in REQUIRED_CHAT_FIELDS

    def test_required_fields_include_channel_id(self) -> None:
        assert "channel_id" in REQUIRED_CHAT_FIELDS

    def test_each_field_has_a_description(self) -> None:
        for field, desc in REQUIRED_CHAT_FIELDS.items():
            assert isinstance(desc, str) and len(desc) > 0, f"Missing description for {field!r}"


# ---------------------------------------------------------------------------
# Step metadata
# ---------------------------------------------------------------------------


class TestConfigureChatStepMetadata:
    def test_step_is_check_safe(self) -> None:
        step = configure_chat_step(config_path=Path("/tmp/does_not_matter.yaml"))
        assert step.check_safe is True


# ---------------------------------------------------------------------------
# No config.yaml exists — interactive mode
# ---------------------------------------------------------------------------


class TestNoConfigInteractive:
    def _inputs(
        self,
        token="Bot.abc123",
        channel="123456789",
        auto_update="y",
        source_path="",
    ) -> list[str]:
        return [token, channel, auto_update, source_path]

    def test_creates_config_yaml(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        results, _ = _run_step(ctx, config_path, inputs=self._inputs())

        assert config_path.exists()
        assert results[0].outcome == StepOutcome.SUCCESS

    def test_config_enables_discord_adapter(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs())

        data = yaml.safe_load(config_path.read_text())
        assert data["chat_adapters"]["discord"]["enabled"] is True

    def test_config_contains_token(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs(token="Bot.mytoken"))

        data = yaml.safe_load(config_path.read_text())
        assert data["chat_adapters"]["discord"]["token"] == "Bot.mytoken"

    def test_config_contains_channel_id(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs(channel="999"))

        data = yaml.safe_load(config_path.read_text())
        assert data["chat_adapters"]["discord"]["channel_id"] == "999"

    def test_config_does_not_write_legacy_chat_section(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs())

        data = yaml.safe_load(config_path.read_text())
        assert "chat" not in data

    def test_config_includes_safe_defaults(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs())

        data = yaml.safe_load(config_path.read_text())
        assert "updates" in data
        assert "monitors" in data
        assert data["updates"]["self_update"]["enabled"] is True
        assert data["updates"]["self_update"]["check_interval"] == "00:05:00"
        assert data["updates"]["self_update"]["snapshots"]["backend"] == "auto"
        assert data["updates"]["self_update"]["snapshots"]["keep_last"] == 20
        assert data["monitors"]["collection_interval"] == "00:01:00"
        assert data["monitors"]["retention"] == "30d 00:00:00"
        assert data["monitors"]["services"]["enabled"] is True
        assert data["monitors"]["services"]["check_interval"] == "00:01:00"
        assert data["monitors"]["services"]["max_restart_attempts"] == 3
        assert data["monitors"]["services"]["journal_lines"] == 20
        assert data["monitors"]["services"]["critical_services"] == []
        assert data["monitors"]["network"]["enabled"] is True
        assert data["monitors"]["network"]["interval"] == "00:01:00"
        assert data["monitors"]["network"]["alert_threshold_bytes_sent"] == 10_000_000
        assert data["monitors"]["network"]["alert_threshold_bytes_recv"] == 10_000_000
        assert data["monitors"]["network"]["alert_cooldown"] == "00:30:00"
        assert data["monitors"]["connections"]["enabled"] is True
        assert data["monitors"]["connections"]["classification"]["attempts_per_ip"] == {
            "suspicious": 3,
            "likely_access_attempt": 8,
        }
        assert data["tools"]["firewall"]["enabled"] is True
        assert data["tools"]["firewall"]["reconcile_interval"] == "00:10:00"
        assert data["tools"]["firewall"]["run_on_startup"] is True
        assert data["tools"]["firewall"]["enforce"] is False
        assert data["tools"]["firewall"]["desired_state"]["default_incoming_policy"] == "deny"
        assert data["tools"]["firewall"]["desired_state"]["allowed_ports"] == [22]
        assert data["updates"]["self_update"]["source_path"]

    def test_auto_update_can_be_disabled(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs(auto_update="n"))

        data = yaml.safe_load(config_path.read_text())
        assert data["updates"]["self_update"]["enabled"] is False

    def test_output_tells_user_where_config_is_saved(self, tmp_path: Path, capsys) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs())

        captured = capsys.readouterr().out
        assert str(config_path) in captured

    def test_each_prompt_includes_field_description(self, tmp_path: Path, capsys) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs())

        captured = capsys.readouterr().out
        for desc in REQUIRED_CHAT_FIELDS.values():
            assert desc in captured, f"Description {desc!r} missing from output"


# ---------------------------------------------------------------------------
# Validation — retry on failure
# ---------------------------------------------------------------------------


class TestValidationRetry:
    def test_invalid_token_prompts_for_reentry(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()

        call_count = 0

        def validator(field: str, value: str, token: str | None = None) -> str | None:
            nonlocal call_count
            if field == "token":
                call_count += 1
                if call_count == 1:
                    return "Invalid bot token"
            return None

        inputs = [
            "bad_token",  # token (fails)
            "good_token",  # token (retry, passes)
            "123",  # channel_id
            "y",  # auto_update
            "",  # source_path (accept detected)
        ]
        buf = io.StringIO()
        step = configure_chat_step(config_path=config_path, validator=validator)
        wizard = SetupWizard(steps=[step], output=buf)
        with (
            patch("builtins.input", side_effect=inputs),
            patch(
                "system_sentinel.setup.config_wizard.subprocess.run",
                side_effect=_make_sudo_run(),
            ),
        ):
            results = wizard.run(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        data = yaml.safe_load(config_path.read_text())
        assert data["chat_adapters"]["discord"]["token"] == "good_token"

    def test_invalid_channel_prompts_for_reentry(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()

        call_count = 0

        def validator(field: str, value: str, token: str | None = None) -> str | None:
            nonlocal call_count
            if field == "channel_id":
                call_count += 1
                if call_count == 1:
                    return "Channel not accessible"
            return None

        inputs = [
            "Bot.token",  # token
            "bad_channel",  # channel_id (fails)
            "good_channel",  # channel_id (retry, passes)
            "y",  # auto_update
            "",  # source_path (accept detected)
        ]
        buf = io.StringIO()
        step = configure_chat_step(config_path=config_path, validator=validator)
        wizard = SetupWizard(steps=[step], output=buf)
        with (
            patch("builtins.input", side_effect=inputs),
            patch(
                "system_sentinel.setup.config_wizard.subprocess.run",
                side_effect=_make_sudo_run(),
            ),
        ):
            results = wizard.run(ctx)

        assert results[0].outcome == StepOutcome.SUCCESS
        data = yaml.safe_load(config_path.read_text())
        assert data["chat_adapters"]["discord"]["channel_id"] == "good_channel"

    def test_validation_error_message_shown_to_user(self, tmp_path: Path, capsys) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()

        call_count = 0

        def validator(field: str, value: str, token: str | None = None) -> str | None:
            nonlocal call_count
            if field == "token":
                call_count += 1
                if call_count == 1:
                    return "401 Unauthorized"
            return None

        inputs = ["bad", "good", "123", "y", ""]
        buf = io.StringIO()
        step = configure_chat_step(config_path=config_path, validator=validator)
        wizard = SetupWizard(steps=[step], output=buf)
        with (
            patch("builtins.input", side_effect=inputs),
            patch(
                "system_sentinel.setup.config_wizard.subprocess.run",
                side_effect=_make_sudo_run(),
            ),
        ):
            wizard.run(ctx)

        captured = capsys.readouterr().out
        assert "401 Unauthorized" in captured


# ---------------------------------------------------------------------------
# config.yaml already exists — validate without overwriting
# ---------------------------------------------------------------------------


class TestConfigAlreadyExists:
    def _write_valid_config(self, path: Path) -> None:
        data = {
            "chat_adapters": {
                "discord": {"enabled": True, "token": "Bot.existingtoken", "channel_id": "789"}
            },
            "updates": {"enabled": True},
            "monitors": {},
        }
        path.write_text(yaml.dump(data))

    def test_valid_existing_config_succeeds_without_prompting(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        self._write_valid_config(config_path)
        original_content = config_path.read_text()

        ctx = WizardContext()
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.SUCCESS
        assert config_path.read_text() == original_content

    def test_config_with_missing_token_reports_failure(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        data: dict[str, object] = {
            "chat_adapters": {"discord": {"enabled": True, "channel_id": "789"}},
        }
        config_path.write_text(yaml.dump(data))

        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.FAILURE
        assert "token" in results[0].message.lower() or (
            results[0].error and "token" in results[0].error.lower()
        )

    def test_config_with_missing_chat_section_reports_failure(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml.dump({"updates": {"enabled": True}}))

        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.FAILURE

    def test_config_with_missing_discord_section_reports_failure(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        data: dict[str, object] = {"chat_adapters": {}}
        config_path.write_text(yaml.dump(data))

        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.FAILURE

    def test_existing_config_not_overwritten_on_failure(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        data: dict[str, object] = {
            "chat_adapters": {"discord": {"enabled": True}},
        }
        config_path.write_text(yaml.dump(data))
        original = config_path.read_text()

        ctx = WizardContext(check_only=True)
        _run_step(ctx, config_path)

        assert config_path.read_text() == original


# ---------------------------------------------------------------------------
# Check-only mode
# ---------------------------------------------------------------------------


class TestCheckOnlyMode:
    def test_valid_config_succeeds_in_check_only(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        data = {
            "chat_adapters": {"discord": {"enabled": True, "token": "Bot.tok", "channel_id": "99"}}
        }
        config_path.write_text(yaml.dump(data))

        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.SUCCESS

    def test_missing_config_fails_in_check_only(self, tmp_path: Path) -> None:
        config_path = tmp_path / "nonexistent.yaml"

        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.FAILURE

    def test_invalid_config_fails_in_check_only(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml.dump({"updates": {}}))

        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.FAILURE


# ---------------------------------------------------------------------------
# Unattended mode
# ---------------------------------------------------------------------------


class TestUnattendedMode:
    def test_no_config_fails_in_unattended_mode(self, tmp_path: Path) -> None:
        config_path = tmp_path / "nonexistent.yaml"

        ctx = WizardContext(unattended=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.FAILURE

    def test_valid_config_succeeds_in_unattended_mode(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        data = {
            "chat_adapters": {"discord": {"enabled": True, "token": "Bot.tok", "channel_id": "99"}}
        }
        config_path.write_text(yaml.dump(data))

        ctx = WizardContext(unattended=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.SUCCESS
