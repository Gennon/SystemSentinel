from __future__ import annotations

import json
from typing import Any

from system_sentinel.core.exceptions import LLMUnavailableError


def require_config_string(config: dict[str, object], key: str, *, provider_name: str) -> str:
    raw = config.get(key)
    if not isinstance(raw, str) or not raw.strip():
        raise LLMUnavailableError(f"{provider_name} provider requires config key {key!r}.")
    return raw.strip()


def as_string(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    return value or None


def usage_tokens(data: dict[str, Any]) -> tuple[int | None, int | None]:
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return None, None
    prompt_tokens_raw = usage.get("prompt_tokens", usage.get("input_tokens"))
    completion_tokens_raw = usage.get("completion_tokens", usage.get("output_tokens"))
    return _as_int(prompt_tokens_raw), _as_int(completion_tokens_raw)


def json_text(data: Any) -> str:
    if isinstance(data, str):
        return data
    return json.dumps(data, ensure_ascii=True)


def _as_int(raw: object) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw)
    return None
