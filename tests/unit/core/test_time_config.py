from __future__ import annotations

import logging

from system_sentinel.core.time_config import parse_duration_from_config


def _logger() -> logging.Logger:
    return logging.getLogger("test.time_config")


def test_parse_duration_standard_hhmmss() -> None:
    result = parse_duration_from_config(
        {"interval": "00:10:00"},
        key="interval",
        default_seconds=60,
        logger=_logger(),
    )
    assert result == 600


def test_parse_duration_supports_large_hours() -> None:
    result = parse_duration_from_config(
        {"interval": "72:00:00"},
        key="interval",
        default_seconds=60,
        logger=_logger(),
    )
    assert result == 72 * 3600


def test_parse_duration_supports_days_prefix() -> None:
    result = parse_duration_from_config(
        {"interval": "3d 00:00:00"},
        key="interval",
        default_seconds=60,
        logger=_logger(),
    )
    assert result == 3 * 24 * 3600


def test_parse_duration_non_canonical_logs_warning(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        result = parse_duration_from_config(
            {"interval": "3d 72:65:98"},
            key="interval",
            default_seconds=60,
            logger=_logger(),
        )
    assert result == (3 * 24 * 3600) + (72 * 3600) + (65 * 60) + 98
    assert "Non-canonical interval value" in caplog.text


def test_parse_duration_invalid_value_uses_default(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        result = parse_duration_from_config(
            {"interval": "foo"},
            key="interval",
            default_seconds=120,
            logger=_logger(),
        )
    assert result == 120
    assert "Invalid interval value" in caplog.text
