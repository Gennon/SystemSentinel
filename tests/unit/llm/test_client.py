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
