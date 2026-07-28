"""Tests for system_sentinel.chat.command_config (US-044)."""

from __future__ import annotations

from datetime import UTC, datetime
import json
import logging
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest
import yaml

from system_sentinel.chat.base import InboundMessage, InboundReaction
from system_sentinel.chat.command_config import (
    SETTABLE_CONFIG_KEYS,
    ConfigChangeProposal,
    ConfigClarificationNeeded,
    _coerce_and_validate,
    _find_schema_key,
    _parse_llm_response,
    apply_config_change,
    format_config_proposal,
    get_nested_value,
    set_nested_value,
)
from system_sentinel.chat.command_dispatcher import ChatCommandDispatcher
from system_sentinel.core.context import AppContext
from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.llm.base import LLMResponse

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _FakeScheduler:
    pass


class _FakeMonitorRegistry:
    @property
    def monitors(self) -> list[object]:
        return []


class _FakeLLMClient:
    def __init__(self, response_text: str) -> None:
        self._response_text = response_text
        self.active_provider_name = "ollama"
        self.is_enabled = True

    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMResponse:
        _ = prompt, system_prompt, model, timeout_seconds
        return LLMResponse(
            text=self._response_text,
            model_used="llama3.2",
            provider="ollama",
            prompt_tokens=10,
            completion_tokens=20,
        )

    async def list_models(self) -> list[str]:
        return ["llama3.2"]

    async def health_check(self) -> bool:
        return True


async def _make_dispatcher(
    tmp_path: Path,
    config: dict[str, Any],
    llm: _FakeLLMClient | None = None,
    config_path: Path | None = None,
) -> ChatCommandDispatcher:
    db = DatabaseConnection(tmp_path / "sentinel.db")
    await db.connect()
    ctx = AppContext(
        audit=AsyncMock(),
        event_bus=AsyncMock(),
        logger=logging.getLogger("test"),
        llm=llm,
    )
    return ChatCommandDispatcher(
        config=config,
        app_ctx=ctx,
        scheduler=_FakeScheduler(),  # type: ignore[arg-type]
        tools={},
        monitor_registry=_FakeMonitorRegistry(),  # type: ignore[arg-type]
        db=db,
        config_path=config_path,
    )


def _message(text: str, channel_id: str = "100") -> InboundMessage:
    return InboundMessage(
        adapter="discord",
        channel_id=channel_id,
        user_id="u1",
        username="admin",
        text=text,
        raw={},
        received_at=datetime.now(UTC),
    )


def _reaction(channel_id: str = "100") -> InboundReaction:
    return InboundReaction(
        adapter="discord",
        channel_id=channel_id,
        user_id="u1",
        username="admin",
        emoji="\u2705",
        raw={},
        received_at=datetime.now(UTC),
    )


def _cfg(channel_id: str = "100") -> dict[str, Any]:
    return {"chat_adapters": {"discord": {"channel_id": channel_id}}}


# ---------------------------------------------------------------------------
# Unit: get_nested_value / set_nested_value
# ---------------------------------------------------------------------------


def test_get_nested_value_existing() -> None:
    config = {"monitors": {"cpu": {"alert_threshold_percent": 85}}}
    assert get_nested_value(config, "monitors.cpu.alert_threshold_percent") == 85


def test_get_nested_value_missing_returns_none() -> None:
    config: dict[str, Any] = {}
    assert get_nested_value(config, "monitors.cpu.alert_threshold_percent") is None


def test_get_nested_value_partial_path_returns_none() -> None:
    config = {"monitors": {}}
    assert get_nested_value(config, "monitors.cpu.alert_threshold_percent") is None


def test_set_nested_value_creates_intermediate_dicts() -> None:
    config: dict[str, Any] = {}
    set_nested_value(config, "monitors.cpu.alert_threshold_percent", 90)
    assert config == {"monitors": {"cpu": {"alert_threshold_percent": 90}}}


def test_set_nested_value_overwrites_existing() -> None:
    config = {"monitors": {"cpu": {"alert_threshold_percent": 80}}}
    set_nested_value(config, "monitors.cpu.alert_threshold_percent", 95)
    assert config["monitors"]["cpu"]["alert_threshold_percent"] == 95


# ---------------------------------------------------------------------------
# Unit: apply_config_change
# ---------------------------------------------------------------------------


def test_apply_config_change_writes_new_value(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump({"monitors": {"cpu": {"alert_threshold_percent": 80}}}))

    old = apply_config_change(config_file, "monitors.cpu.alert_threshold_percent", 90.0)

    assert old == 80
    updated = yaml.safe_load(config_file.read_text())
    assert updated["monitors"]["cpu"]["alert_threshold_percent"] == 90.0


def test_apply_config_change_creates_key_if_absent(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump({}))

    old = apply_config_change(config_file, "monitors.ram.alert_threshold_percent", 75.0)

    assert old is None
    updated = yaml.safe_load(config_file.read_text())
    assert updated["monitors"]["ram"]["alert_threshold_percent"] == 75.0


def test_apply_config_change_returns_old_value(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump({"monitors": {"disk": {"alert_threshold_percent": 70}}}))

    old = apply_config_change(config_file, "monitors.disk.alert_threshold_percent", 85.0)
    assert old == 70


# ---------------------------------------------------------------------------
# Unit: _parse_llm_response
# ---------------------------------------------------------------------------


def test_parse_llm_response_change_action() -> None:
    response = json.dumps(
        {
            "action": "change",
            "key_path": "monitors.cpu.alert_threshold_percent",
            "new_value": 90,
        }
    )
    result = _parse_llm_response(response, {"monitors": {"cpu": {"alert_threshold_percent": 80}}})
    assert isinstance(result, ConfigChangeProposal)
    assert result.key_path == "monitors.cpu.alert_threshold_percent"
    assert result.new_value == 90.0
    assert result.old_value == 80


def test_parse_llm_response_clarify_action() -> None:
    response = json.dumps({"action": "clarify", "question": "Which threshold do you mean?"})
    result = _parse_llm_response(response, {})
    assert isinstance(result, ConfigClarificationNeeded)
    assert "Which threshold" in result.question


def test_parse_llm_response_unknown_key_returns_clarification() -> None:
    response = json.dumps({"action": "change", "key_path": "monitors.unknown.key", "new_value": 42})
    result = _parse_llm_response(response, {})
    assert isinstance(result, ConfigClarificationNeeded)
    assert "monitors.unknown.key" in result.question


def test_parse_llm_response_invalid_json_returns_clarification() -> None:
    result = _parse_llm_response("not json at all", {})
    assert isinstance(result, ConfigClarificationNeeded)


def test_parse_llm_response_handles_markdown_code_block() -> None:
    inner = json.dumps(
        {
            "action": "change",
            "key_path": "monitors.ram.alert_threshold_percent",
            "new_value": 85,
        }
    )
    response = f"```json\n{inner}\n```"
    result = _parse_llm_response(response, {})
    assert isinstance(result, ConfigChangeProposal)
    assert result.new_value == 85.0


# ---------------------------------------------------------------------------
# Unit: _coerce_and_validate
# ---------------------------------------------------------------------------


def test_coerce_number_from_int() -> None:
    schema = _find_schema_key("monitors.cpu.alert_threshold_percent")
    assert schema is not None
    val, err = _coerce_and_validate(90, schema)
    assert err is None
    assert val == 90.0


def test_coerce_integer_from_float() -> None:
    schema = _find_schema_key("monitors.cpu.alert_consecutive_intervals")
    assert schema is not None
    val, err = _coerce_and_validate(3.0, schema)
    assert err is None
    assert val == 3


def test_validate_rejects_value_above_max() -> None:
    schema = _find_schema_key("monitors.cpu.alert_threshold_percent")
    assert schema is not None
    val, err = _coerce_and_validate(105, schema)
    assert err is not None
    assert val is None


def test_validate_rejects_value_below_min() -> None:
    schema = _find_schema_key("monitors.cpu.alert_consecutive_intervals")
    assert schema is not None
    val, err = _coerce_and_validate(0, schema)
    assert err is not None
    assert val is None


def test_coerce_non_numeric_string_returns_error() -> None:
    schema = _find_schema_key("monitors.cpu.alert_threshold_percent")
    assert schema is not None
    val, err = _coerce_and_validate("not-a-number", schema)
    assert err is not None
    assert val is None


# ---------------------------------------------------------------------------
# Unit: format_config_proposal
# ---------------------------------------------------------------------------


def test_format_config_proposal_contains_key_and_values() -> None:
    proposal = ConfigChangeProposal(
        key_path="monitors.cpu.alert_threshold_percent",
        old_value=80,
        new_value=90.0,
        description="CPU usage alert threshold percentage",
    )
    text = format_config_proposal(proposal)
    assert "monitors.cpu.alert_threshold_percent" in text
    assert "80" in text
    assert "90.0" in text
    assert "\u2705" in text


def test_format_config_proposal_shows_not_set_for_none_old_value() -> None:
    proposal = ConfigChangeProposal(
        key_path="monitors.ram.alert_threshold_percent",
        old_value=None,
        new_value=85.0,
        description="RAM usage alert threshold percentage",
    )
    text = format_config_proposal(proposal)
    assert "not set" in text


# ---------------------------------------------------------------------------
# Unit: SETTABLE_CONFIG_KEYS coverage
# ---------------------------------------------------------------------------


def test_settable_config_keys_all_have_required_fields() -> None:
    for key in SETTABLE_CONFIG_KEYS:
        assert key.path
        assert key.description
        assert key.value_type in {"number", "integer", "string", "boolean"}


# ---------------------------------------------------------------------------
# Integration: !config command through ChatCommandDispatcher
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_config_command_no_llm_configured(tmp_path: Path) -> None:
    dispatcher = await _make_dispatcher(tmp_path, _cfg(), llm=None)
    response = await dispatcher.handle_message(
        _message("!config set cpu to 90"), ["!config", "set", "cpu", "to", "90"]
    )
    assert response is not None
    assert "LLM" in response.text or "not configured" in response.text.lower()


@pytest.mark.asyncio
async def test_config_command_no_config_path(tmp_path: Path) -> None:
    llm = _FakeLLMClient(
        json.dumps(
            {
                "action": "change",
                "key_path": "monitors.cpu.alert_threshold_percent",
                "new_value": 90,
            }
        )
    )
    dispatcher = await _make_dispatcher(tmp_path, _cfg(), llm=llm, config_path=None)
    response = await dispatcher.handle_message(_message("!config set cpu to 90"), ["!config"])
    assert response is not None
    assert "not available" in response.text.lower()


@pytest.mark.asyncio
async def test_config_command_missing_argument(tmp_path: Path) -> None:
    llm = _FakeLLMClient("")
    dispatcher = await _make_dispatcher(tmp_path, _cfg(), llm=llm)
    response = await dispatcher.handle_message(_message("!config"), ["!config"])
    assert response is not None
    assert "Usage" in response.text


@pytest.mark.asyncio
async def test_config_command_llm_returns_clarification(tmp_path: Path) -> None:
    llm = _FakeLLMClient(json.dumps({"action": "clarify", "question": "Which threshold?"}))
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump({}))
    dispatcher = await _make_dispatcher(tmp_path, _cfg(), llm=llm, config_path=config_file)
    response = await dispatcher.handle_message(
        _message("!config change threshold"), ["!config", "change", "threshold"]
    )
    assert response is not None
    assert "Which threshold?" in response.text


@pytest.mark.asyncio
async def test_config_command_proposes_change_without_writing(tmp_path: Path) -> None:
    llm = _FakeLLMClient(
        json.dumps(
            {
                "action": "change",
                "key_path": "monitors.cpu.alert_threshold_percent",
                "new_value": 90,
            }
        )
    )
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump({"monitors": {"cpu": {"alert_threshold_percent": 80}}}))
    dispatcher = await _make_dispatcher(tmp_path, _cfg(), llm=llm, config_path=config_file)
    response = await dispatcher.handle_message(
        _message("!config set cpu alert threshold to 90%"), ["!config"]
    )
    assert response is not None
    assert "monitors.cpu.alert_threshold_percent" in response.text
    assert "90" in response.text
    assert "\u2705" in response.text
    # File must NOT be written yet
    saved = yaml.safe_load(config_file.read_text())
    assert saved["monitors"]["cpu"]["alert_threshold_percent"] == 80


@pytest.mark.asyncio
async def test_config_confirmation_applies_change_to_file(tmp_path: Path) -> None:
    llm = _FakeLLMClient(
        json.dumps(
            {
                "action": "change",
                "key_path": "monitors.cpu.alert_threshold_percent",
                "new_value": 90,
            }
        )
    )
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump({"monitors": {"cpu": {"alert_threshold_percent": 80}}}))
    dispatcher = await _make_dispatcher(tmp_path, _cfg(), llm=llm, config_path=config_file)

    await dispatcher.handle_message(_message("!config set cpu alert threshold to 90%"), ["!config"])
    result = await dispatcher.handle_reaction(_reaction())

    assert result is not None
    assert "Config updated" in result.text
    assert "monitors.cpu.alert_threshold_percent" in result.text

    saved = yaml.safe_load(config_file.read_text())
    assert saved["monitors"]["cpu"]["alert_threshold_percent"] == 90.0


@pytest.mark.asyncio
async def test_config_confirmation_audit_log_contains_diff(tmp_path: Path) -> None:
    llm = _FakeLLMClient(
        json.dumps(
            {
                "action": "change",
                "key_path": "monitors.ram.alert_threshold_percent",
                "new_value": 75,
            }
        )
    )
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump({}))
    dispatcher = await _make_dispatcher(tmp_path, _cfg(), llm=llm, config_path=config_file)

    await dispatcher.handle_message(_message("!config set ram to 75"), ["!config"])
    await dispatcher.handle_reaction(_reaction())

    audit_mock: AsyncMock = dispatcher._ctx.audit  # type: ignore[attr-defined]
    config_calls = [
        c
        for c in audit_mock.append.call_args_list
        if c.kwargs.get("action_type") == "config_change"
    ]
    assert len(config_calls) == 1
    details = config_calls[0].kwargs["details"]
    assert details["key_path"] == "monitors.ram.alert_threshold_percent"
    assert details["new_value"] == 75.0
    assert "original_request" in details
    assert "diff" in details
    assert config_calls[0].kwargs["outcome"] == "success"


@pytest.mark.asyncio
async def test_config_command_in_help_output(tmp_path: Path) -> None:
    dispatcher = await _make_dispatcher(tmp_path, _cfg())
    response = await dispatcher.handle_message(_message("!help"), ["!help"])
    assert response is not None
    assert "!config" in response.text
