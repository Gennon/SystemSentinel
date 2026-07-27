from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

DEFAULT_MONITORED_PATHS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
)


@dataclass(frozen=True)
class MonitoredFileTarget:
    path: str
    source_path: str


def normalize_monitored_paths(raw: object) -> list[str]:
    if isinstance(raw, list):
        values = [str(item).strip() for item in raw if str(item).strip()]
        if values:
            return [_normalize_path(path) for path in values]
    return [_normalize_path(path) for path in DEFAULT_MONITORED_PATHS]


def expand_monitored_targets(monitored_paths: list[str]) -> list[MonitoredFileTarget]:
    discovered: list[MonitoredFileTarget] = []
    seen_paths: set[str] = set()
    for source_path in monitored_paths:
        source = _normalize_path(source_path)
        if not source:
            continue
        source_obj = Path(source)
        if source_obj.is_dir():
            for file_path in sorted(source_obj.rglob("*")):
                if not file_path.is_file():
                    continue
                normalized = _normalize_path(str(file_path))
                if normalized in seen_paths:
                    continue
                discovered.append(MonitoredFileTarget(path=normalized, source_path=source))
                seen_paths.add(normalized)
            continue
        if source in seen_paths:
            continue
        discovered.append(MonitoredFileTarget(path=source, source_path=source))
        seen_paths.add(source)
    return discovered


def _normalize_path(raw_path: str) -> str:
    expanded = os.path.expandvars(raw_path)
    path = Path(expanded).expanduser().resolve(strict=False)
    return str(path)
