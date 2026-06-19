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
    def test_required_fields_include_provider(self) -> None:
        assert "provider" in REQUIRED_CHAT_FIELDS

    def test_required_fields_include_token(self) -> None:
        assert "token" in REQUIRED_CHAT_FIELDS

    def test_required_fields_include_channel_id(self) -> None:
        assert "channel_id" in REQUIRED_CHAT_FIELDS

    def test_required_fields_include_allowed_users(self) -> None:
        assert "allowed_users" in REQUIRED_CHAT_FIELDS

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
        self, provider="discord", token="Bot.abc123", channel="123456789", users="42"
    ) -> list[str]:
        return [provider, token, channel, users]

    def test_creates_config_yaml(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        results, _ = _run_step(ctx, config_path, inputs=self._inputs())

        assert config_path.exists()
        assert results[0].outcome == StepOutcome.SUCCESS

    def test_config_contains_provider(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs(provider="discord"))

        data = yaml.safe_load(config_path.read_text())
        assert data["chat"]["provider"] == "discord"

    def test_config_contains_token(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs(token="Bot.mytoken"))

        data = yaml.safe_load(config_path.read_text())
        assert data["chat"]["token"] == "Bot.mytoken"

    def test_config_contains_channel_id(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs(channel="999"))

        data = yaml.safe_load(config_path.read_text())
        assert data["chat"]["channel_id"] == "999"

    def test_config_contains_allowed_users(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs(users="111,222"))

        data = yaml.safe_load(config_path.read_text())
        assert "111" in data["chat"]["allowed_users"]
        assert "222" in data["chat"]["allowed_users"]

    def test_config_includes_safe_defaults(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        ctx = WizardContext()
        _run_step(ctx, config_path, inputs=self._inputs())

        data = yaml.safe_load(config_path.read_text())
        assert "updates" in data
        assert "monitors" in data

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
            "discord",  # provider
            "bad_token",  # token (fails)
            "good_token",  # token (retry, passes)
            "123",  # channel_id
            "42",  # allowed_users
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
        assert data["chat"]["token"] == "good_token"

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
            "discord",  # provider
            "Bot.token",  # token
            "bad_channel",  # channel_id (fails)
            "good_channel",  # channel_id (retry, passes)
            "42",  # allowed_users
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
        assert data["chat"]["channel_id"] == "good_channel"

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

        inputs = ["discord", "bad", "good", "123", "42"]
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
            "chat": {
                "provider": "discord",
                "token": "Bot.existingtoken",
                "channel_id": "789",
                "allowed_users": ["10"],
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
            "chat": {"provider": "discord", "channel_id": "789", "allowed_users": ["10"]},
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

    def test_config_with_empty_allowed_users_reports_failure(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        data: dict[str, object] = {
            "chat": {
                "provider": "discord",
                "token": "Bot.tok",
                "channel_id": "789",
                "allowed_users": [],
            },
        }
        config_path.write_text(yaml.dump(data))

        ctx = WizardContext(check_only=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.FAILURE

    def test_existing_config_not_overwritten_on_failure(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yaml"
        data: dict[str, object] = {
            "chat": {"provider": "discord"},
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
            "chat": {
                "provider": "discord",
                "token": "Bot.tok",
                "channel_id": "99",
                "allowed_users": ["1"],
            }
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
            "chat": {
                "provider": "discord",
                "token": "Bot.tok",
                "channel_id": "99",
                "allowed_users": ["1"],
            }
        }
        config_path.write_text(yaml.dump(data))

        ctx = WizardContext(unattended=True)
        results, _ = _run_step(ctx, config_path)

        assert results[0].outcome == StepOutcome.SUCCESS
