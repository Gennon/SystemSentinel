from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging

_DURATION_RE = re.compile(r"^\d{2}:\d{2}:\d{2}$")


def parse_duration_hhmmss(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not _DURATION_RE.fullmatch(raw):
        return None
    hours_s, minutes_s, seconds_s = raw.split(":")
    hours = int(hours_s)
    minutes = int(minutes_s)
    seconds = int(seconds_s)
    if minutes > 59 or seconds > 59:
        return None
    return float(hours * 3600 + minutes * 60 + seconds)


def parse_duration_from_config(
    config: dict[str, Any],
    *,
    key: str,
    default_seconds: float,
    logger: logging.Logger,
) -> float:
    raw = config.get(key)
    if raw is None:
        return default_seconds
    parsed = parse_duration_hhmmss(raw)
    if parsed is None:
        logger.warning(
            "Invalid %s value %r; expected HH:MM:SS. Using default %s.",
            key,
            raw,
            _format_seconds(default_seconds),
        )
        return default_seconds
    return parsed


def _format_seconds(total_seconds: float) -> str:
    rounded = int(total_seconds)
    hours = rounded // 3600
    minutes = (rounded % 3600) // 60
    seconds = rounded % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
