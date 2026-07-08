from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Alert:
    """Structured representation of a fired alert, before chat formatting."""

    event_type: str
    title: str
    body: str
    severity: AlertSeverity
    fields: dict[str, str] | None = None
