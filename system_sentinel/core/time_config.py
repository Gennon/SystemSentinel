from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging

_EXTENDED_DURATION_RE = re.compile(
    r"^(?:(?P<days>\d+)\s*[dD]\s+)?(?P<hours>\d+):(?P<minutes>\d+):(?P<seconds>\d+)$"
)


def parse_duration_hhmmss(value: object) -> tuple[float, bool] | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    match = _EXTENDED_DURATION_RE.fullmatch(raw)
    if match is None:
        return None
    days = int(match.group("days") or 0)
    hours = int(match.group("hours"))
    minutes = int(match.group("minutes"))
    seconds = int(match.group("seconds"))
    total_seconds = float(days * 86400 + hours * 3600 + minutes * 60 + seconds)
    is_non_canonical = bool(days > 0 and hours >= 24) or minutes > 59 or seconds > 59
    return total_seconds, is_non_canonical


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
            "Invalid %s value %r; expected HH:MM:SS or <days>d HH:MM:SS. Using default %s.",
            key,
            raw,
            _format_seconds(default_seconds),
        )
        return default_seconds
    parsed_seconds, is_non_canonical = parsed
    if is_non_canonical:
        logger.warning(
            "Non-canonical %s value %r; interpreting as %s.",
            key,
            raw,
            _format_seconds(parsed_seconds),
        )
    return parsed_seconds


def _format_seconds(total_seconds: float) -> str:
    rounded = int(total_seconds)
    hours = rounded // 3600
    minutes = (rounded % 3600) // 60
    seconds = rounded % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
