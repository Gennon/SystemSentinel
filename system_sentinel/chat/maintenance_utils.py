from __future__ import annotations

from datetime import UTC, datetime
import fnmatch
import os
from pathlib import Path
from typing import Any

import psutil


def build_storage_report(paths: list[str]) -> str:
    lines: list[str] = []
    for raw_path in paths:
        path = str(raw_path).strip()
        if not path:
            continue
        if not os.path.exists(path):
            lines.append(f"{path}: missing")
            continue
        try:
            usage = psutil.disk_usage(path)
        except OSError as exc:
            lines.append(f"{path}: permission denied ({exc})")
            continue
        lines.append(
            f"{path}: used={usage.used} free={usage.free} total={usage.total} ({usage.percent:.1f}%)"
        )
        top_dirs = _top_subdirs_by_size(path, limit=10)
        for name, size in top_dirs:
            lines.append(f"- {name}: {size} bytes")
    return "\n".join(lines) if lines else "No storage report data available."


def run_cleanup_rules(raw_rules: list[Any]) -> tuple[int, int, int]:
    deleted = 0
    reclaimed = 0
    failed = 0
    now = datetime.now(UTC)
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            continue
        path = str(raw_rule.get("path", "")).strip()
        pattern = str(raw_rule.get("pattern", "*")).strip() or "*"
        if not path:
            continue
        older_than = parse_older_than_seconds(raw_rule.get("older_than"))
        if older_than is None:
            continue

        root = Path(path)
        if not root.exists() or not root.is_dir():
            continue

        for candidate in root.rglob("*"):
            if not candidate.is_file():
                continue
            if not fnmatch.fnmatch(candidate.name, pattern):
                continue
            try:
                modified = datetime.fromtimestamp(candidate.stat().st_mtime, tz=UTC)
                if (now - modified).total_seconds() < older_than:
                    continue
                size = candidate.stat().st_size
                candidate.unlink()
                deleted += 1
                reclaimed += int(size)
            except OSError:
                failed += 1
    return deleted, reclaimed, failed


def parse_older_than_seconds(raw: object) -> float | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    if not value:
        return None
    days = 0
    if "d " in value:
        day_part, value = value.split("d ", maxsplit=1)
        if day_part.isdigit():
            days = int(day_part)
    parts = value.split(":")
    if len(parts) != 3:
        return None
    try:
        hours = int(parts[0])
        minutes = int(parts[1])
        seconds = int(parts[2])
    except ValueError:
        return None
    return float(days * 86400 + hours * 3600 + minutes * 60 + seconds)


def _top_subdirs_by_size(root: str, limit: int = 10) -> list[tuple[str, int]]:
    root_path = Path(root)
    if not root_path.exists() or not root_path.is_dir():
        return []
    sizes: list[tuple[str, int]] = []
    try:
        children = list(root_path.iterdir())
    except OSError:
        return []
    for child in children:
        if not child.is_dir():
            continue
        size = 0
        for dirpath, _dirnames, filenames in os.walk(child, onerror=lambda _err: None):
            for filename in filenames:
                file_path = Path(dirpath) / filename
                try:
                    size += file_path.stat().st_size
                except OSError:
                    continue
        sizes.append((str(child), size))
    sizes.sort(key=lambda item: item[1], reverse=True)
    return sizes[:limit]
