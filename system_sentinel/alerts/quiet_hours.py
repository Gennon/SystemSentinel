from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
import re

_QUIET_HOURS_RE = re.compile(
    r"^\s*(?P<start_hour>\d{1,2}):(?P<start_minute>\d{2})\s*-\s*(?P<end_hour>\d{1,2}):(?P<end_minute>\d{2})\s*$"
)


@dataclass(frozen=True)
class QuietHoursWindow:
    start: time
    end: time

    @property
    def label(self) -> str:
        return f"{self.start:%H:%M}-{self.end:%H:%M}"

    def is_active(self, now: datetime) -> bool:
        current = now.timetz().replace(tzinfo=None)
        if self.start == self.end:
            return True
        if self.start < self.end:
            return self.start <= current < self.end
        return current >= self.start or current < self.end


def parse_quiet_hours_window(value: object) -> QuietHoursWindow | None:
    if not isinstance(value, str):
        return None
    match = _QUIET_HOURS_RE.fullmatch(value)
    if match is None:
        return None
    start_hour = int(match.group("start_hour"))
    start_minute = int(match.group("start_minute"))
    end_hour = int(match.group("end_hour"))
    end_minute = int(match.group("end_minute"))
    if start_hour > 23 or end_hour > 23 or start_minute > 59 or end_minute > 59:
        return None
    return QuietHoursWindow(
        start=time(hour=start_hour, minute=start_minute),
        end=time(hour=end_hour, minute=end_minute),
    )


def quiet_hours_end(now: datetime, window: QuietHoursWindow) -> datetime:
    now_utc = now.astimezone(UTC)
    end_today = now_utc.replace(
        hour=window.end.hour,
        minute=window.end.minute,
        second=0,
        microsecond=0,
    )
    if window.start == window.end:
        if end_today <= now_utc:
            return end_today + timedelta(days=1)
        return end_today
    if window.start < window.end:
        return end_today if now_utc < end_today else end_today + timedelta(days=1)

    if now_utc.timetz().replace(tzinfo=None) >= window.start:
        return end_today + timedelta(days=1)
    return end_today
