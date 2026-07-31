from __future__ import annotations

import logging

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.llm.base import BaseLLMProvider, LLMRequest, LLMResponse
from system_sentinel.llm.client import LLMClient


class _FakeProvider(BaseLLMProvider):
    name = "fake"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            text=f"echo:{request.prompt}",
            model_used=request.model or "fake-default",
            provider=self.name,
        )

    async def list_models(self) -> list[str]:
        return ["fake-default", "fake-pro"]

    async def health_check(self) -> bool:
        return True


def _provider() -> _FakeProvider:
    ctx = AppContext(audit=object(), event_bus=object(), logger=logging.getLogger("test"))  # type: ignore[arg-type]
    return _FakeProvider({"enabled": True, "model": "fake-default"}, ctx)


@pytest.mark.asyncio
async def test_complete_uses_configured_provider() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={"enabled": True, "provider": "fake"},
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    response = await client.complete(prompt="hello", model="fake-pro")
    assert response.provider == "fake"
    assert response.model_used == "fake-pro"
    assert response.text == "echo:hello"


@pytest.mark.asyncio
async def test_complete_raises_when_disabled() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={"enabled": False, "provider": "fake"},
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    with pytest.raises(LLMUnavailableError):
        await client.complete(prompt="hello")


@pytest.mark.asyncio
async def test_list_models_proxies_to_provider() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={"enabled": True, "provider": "fake"},
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    models = await client.list_models()
    assert models == ["fake-default", "fake-pro"]


# --- Routing tests (US-033) ---


@pytest.mark.asyncio
async def test_active_model_returns_configured_model() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={"enabled": True, "provider": "fake", "model": "llama3.2"},
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    assert client.active_model == "llama3.2"


@pytest.mark.asyncio
async def test_active_model_is_none_when_not_set() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={"enabled": True, "provider": "fake"},
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    assert client.active_model is None


@pytest.mark.asyncio
async def test_routing_rule_selects_model_by_command_type() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={
            "enabled": True,
            "provider": "fake",
            "model": "default-model",
            "routing_rules": [{"command_type": "checkup", "model": "heavy-model"}],
        },
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    response = await client.complete(prompt="run checkup", command_type="checkup")
    assert response.model_used == "heavy-model"
    assert response.matched_rule is not None
    assert response.matched_rule["command_type"] == "checkup"


@pytest.mark.asyncio
async def test_no_matching_rule_uses_default_model() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={
            "enabled": True,
            "provider": "fake",
            "model": "default-model",
            "routing_rules": [{"command_type": "checkup", "model": "heavy-model"}],
        },
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    response = await client.complete(prompt="ask something", command_type="ask")
    assert response.model_used == "default-model"
    assert response.matched_rule is None


@pytest.mark.asyncio
async def test_explicit_model_overrides_routing() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={
            "enabled": True,
            "provider": "fake",
            "model": "default-model",
            "routing_rules": [{"command_type": "ask", "model": "routed-model"}],
        },
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    response = await client.complete(prompt="hello", model="explicit-override", command_type="ask")
    assert response.model_used == "explicit-override"


@pytest.mark.asyncio
async def test_routing_to_different_provider() -> None:
    class _AltProvider(BaseLLMProvider):
        name = "alt"

        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(
                text="alt-response", model_used=request.model or "alt-m", provider="alt"
            )

        async def list_models(self) -> list[str]:
            return []

        async def health_check(self) -> bool:
            return True

    ctx = AppContext(audit=object(), event_bus=object(), logger=logging.getLogger("test"))  # type: ignore[arg-type]
    fake = _FakeProvider({"enabled": True}, ctx)
    alt = _AltProvider({"enabled": True}, ctx)

    client = LLMClient(
        llm_config={
            "enabled": True,
            "provider": "fake",
            "model": "default-model",
            "routing_rules": [{"command_type": "ask", "provider": "alt", "model": "alt-model"}],
        },
        providers={"fake": fake, "alt": alt},
        logger=logging.getLogger("test"),
    )
    response = await client.complete(prompt="hello", command_type="ask")
    assert response.provider == "alt"
    assert response.model_used == "alt-model"


@pytest.mark.asyncio
async def test_routing_fallback_when_no_command_type() -> None:
    provider = _provider()
    client = LLMClient(
        llm_config={
            "enabled": True,
            "provider": "fake",
            "model": "default-model",
            "routing_rules": [{"command_type": "checkup", "model": "heavy-model"}],
        },
        providers={"fake": provider},
        logger=logging.getLogger("test"),
    )
    response = await client.complete(prompt="hello")
    assert response.model_used == "default-model"
    assert response.matched_rule is None
