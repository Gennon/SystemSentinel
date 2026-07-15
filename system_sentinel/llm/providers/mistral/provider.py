from __future__ import annotations

from typing import Any

import httpx

from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.llm.base import BaseLLMProvider, LLMRequest, LLMResponse
from system_sentinel.llm.providers._common import as_string, require_config_string, usage_tokens


class MistralProvider(BaseLLMProvider):
    name = "mistral"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        model = request.model or as_string(self.config.get("model"))
        if model is None:
            raise LLMUnavailableError("Mistral provider requires a model in config or request.")
        endpoint = self._endpoint("/v1/chat/completions")
        headers = self._headers()

        messages: list[dict[str, str]] = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})
        payload: dict[str, object] = {
            "model": model,
            "messages": messages,
        }
        temperature = self.config.get("temperature")
        if isinstance(temperature, (int, float)):
            payload["temperature"] = float(temperature)

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
            raise LLMUnavailableError(f"Mistral request failed: {exc}") from exc

        data = response.json()
        if not isinstance(data, dict):
            raise LLMUnavailableError("Mistral response payload was not a JSON object.")
        text = _extract_mistral_text(data)
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
            raise LLMUnavailableError(f"Mistral model listing failed: {exc}") from exc

        data = response.json()
        if not isinstance(data, dict):
            raise LLMUnavailableError("Mistral model listing payload was not a JSON object.")
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
        api_key = require_config_string(self.config, "api_key", provider_name="Mistral")
        return {"Authorization": f"Bearer {api_key}"}

    def _endpoint(self, path: str) -> str:
        base = as_string(self.config.get("endpoint")) or "https://api.mistral.ai"
        return f"{base.rstrip('/')}{path}"


def _extract_mistral_text(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMUnavailableError("Mistral response did not include any choices.")
    first = choices[0]
    if not isinstance(first, dict):
        raise LLMUnavailableError("Mistral response choice was invalid.")
    message = first.get("message")
    if not isinstance(message, dict):
        raise LLMUnavailableError("Mistral response choice missing message payload.")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise LLMUnavailableError("Mistral response content was empty.")
    return content.strip()
