from __future__ import annotations

from typing import Any

import httpx

from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.llm.base import BaseLLMProvider, LLMRequest, LLMResponse
from system_sentinel.llm.providers._common import as_string, require_config_string, usage_tokens

_DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(BaseLLMProvider):
    name = "anthropic"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        model = request.model or as_string(self.config.get("model"))
        if model is None:
            raise LLMUnavailableError("Anthropic provider requires a model in config or request.")
        endpoint = self._endpoint("/v1/messages")
        headers = self._headers()
        payload: dict[str, object] = {
            "model": model,
            "messages": [{"role": "user", "content": request.prompt}],
            "max_tokens": self._max_tokens(),
        }
        if request.system_prompt:
            payload["system"] = request.system_prompt

        timeout_seconds = max(request.timeout_seconds, 1.0)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                    timeout=timeout_seconds,
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(f"Anthropic request failed: {exc}") from exc

        data = response.json()
        if not isinstance(data, dict):
            raise LLMUnavailableError("Anthropic response payload was not a JSON object.")
        text = _extract_anthropic_text(data)
        prompt_tokens, completion_tokens = usage_tokens(data)
        model_used_raw = data.get("model")
        model_used = model_used_raw if isinstance(model_used_raw, str) else model
        return LLMResponse(
            text=text,
            model_used=model_used,
            provider=self.name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    async def list_models(self) -> list[str]:
        endpoint = self._endpoint("/v1/models")
        headers = self._headers()
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(endpoint, headers=headers, timeout=10.0)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(f"Anthropic model listing failed: {exc}") from exc

        data = response.json()
        if not isinstance(data, dict):
            raise LLMUnavailableError("Anthropic model listing payload was not a JSON object.")
        rows = data.get("data")
        if not isinstance(rows, list):
            return []
        model_ids: list[str] = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            model_id = item.get("id")
            if isinstance(model_id, str) and model_id:
                model_ids.append(model_id)
        return sorted(model_ids)

    async def health_check(self) -> bool:
        await self.list_models()
        return True

    def _headers(self) -> dict[str, str]:
        api_key = require_config_string(self.config, "api_key", provider_name="Anthropic")
        version = as_string(self.config.get("api_version")) or _DEFAULT_ANTHROPIC_VERSION
        return {
            "x-api-key": api_key,
            "anthropic-version": version,
            "content-type": "application/json",
        }

    def _max_tokens(self) -> int:
        raw = self.config.get("max_tokens")
        if isinstance(raw, int) and raw > 0:
            return raw
        if isinstance(raw, float) and raw > 0:
            return int(raw)
        return 1024

    def _endpoint(self, path: str) -> str:
        base = as_string(self.config.get("endpoint")) or "https://api.anthropic.com"
        return f"{base.rstrip('/')}{path}"


def _extract_anthropic_text(data: dict[str, Any]) -> str:
    content = data.get("content")
    if not isinstance(content, list) or not content:
        raise LLMUnavailableError("Anthropic response did not include content segments.")
    parts: list[str] = []
    for segment in content:
        if not isinstance(segment, dict):
            continue
        if segment.get("type") != "text":
            continue
        text = segment.get("text")
        if isinstance(text, str) and text.strip():
            parts.append(text.strip())
    if not parts:
        raise LLMUnavailableError("Anthropic response did not include text content.")
    return "\n".join(parts)
