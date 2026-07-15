from __future__ import annotations

import httpx

from system_sentinel.core.exceptions import LLMUnavailableError
from system_sentinel.llm.base import BaseLLMProvider, LLMRequest, LLMResponse
from system_sentinel.llm.providers._common import as_string


class OllamaProvider(BaseLLMProvider):
    name = "ollama"

    async def complete(self, request: LLMRequest) -> LLMResponse:
        endpoint = self._endpoint("/api/chat")
        model = request.model or as_string(self.config.get("model"))
        if model is None:
            raise LLMUnavailableError("Ollama provider requires a model in config or request.")

        messages: list[dict[str, str]] = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        payload: dict[str, object] = {
            "model": model,
            "messages": messages,
            "stream": False,
        }
        timeout_seconds = max(request.timeout_seconds, 1.0)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(endpoint, json=payload, timeout=timeout_seconds)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(f"Ollama request failed: {exc}") from exc

        data = response.json()
        if not isinstance(data, dict):
            raise LLMUnavailableError("Ollama response payload was not a JSON object.")
        message = data.get("message")
        if not isinstance(message, dict):
            raise LLMUnavailableError("Ollama response missing message object.")
        text = message.get("content")
        if not isinstance(text, str):
            raise LLMUnavailableError("Ollama response missing message content.")
        prompt_tokens = _as_int(data.get("prompt_eval_count"))
        completion_tokens = _as_int(data.get("eval_count"))
        model_used_raw = data.get("model")
        model_used = model_used_raw if isinstance(model_used_raw, str) else model
        return LLMResponse(
            text=text.strip(),
            model_used=model_used,
            provider=self.name,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

    async def list_models(self) -> list[str]:
        endpoint = self._endpoint("/api/tags")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(endpoint, timeout=10.0)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailableError(f"Ollama model listing failed: {exc}") from exc

        data = response.json()
        if not isinstance(data, dict):
            raise LLMUnavailableError("Ollama model listing payload was not a JSON object.")
        models = data.get("models")
        if not isinstance(models, list):
            return []
        names: list[str] = []
        for item in models:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name:
                names.append(name)
        return names

    async def health_check(self) -> bool:
        await self.list_models()
        return True

    def _endpoint(self, path: str) -> str:
        base = as_string(self.config.get("endpoint")) or "http://localhost:11434"
        return f"{base.rstrip('/')}{path}"


def _as_int(raw: object) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw)
    return None
