from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import fnmatch
import os
from pathlib import Path
from typing import Any

import psutil


@dataclass(frozen=True)
class CleanupCandidate:
    path: str
    size_bytes: int
    rule: dict[str, Any]
    dry_run: bool


def build_storage_report(paths: list[str], disk_alert_threshold_percent: float = 85.0) -> str:
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
        status = "ALERT" if usage.percent > disk_alert_threshold_percent else "OK"
        lines.append(
            f"{path}: used={_format_bytes(usage.used)} free={_format_bytes(usage.free)} "
            f"total={_format_bytes(usage.total)} "
            f"({usage.percent:.1f}%) status={status} threshold>{disk_alert_threshold_percent:.1f}%"
        )
        top_dirs = _top_subdirs_by_size(path, limit=10)
        lines.append(f"Top {len(top_dirs)} subdirectories by size:")
        for name, size in top_dirs:
            lines.append(f"- {name}: {_format_bytes(size)}")
    return "\n".join(lines) if lines else "No storage report data available."


def run_cleanup_rules(
    raw_rules: list[Any], *, now: datetime | None = None
) -> list[CleanupCandidate]:
    scan_time = now or datetime.now(UTC)
    seen_paths: set[str] = set()
    matches: list[CleanupCandidate] = []
    for rule_index, raw_rule in enumerate(raw_rules):
        rule = _coerce_cleanup_rule(raw_rule, rule_index=rule_index)
        if rule is None:
            continue
        root = Path(rule["path"])
        if not root.exists() or not root.is_dir():
            continue

        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            base_dir = Path(dirpath)
            dirnames[:] = [name for name in dirnames if not (base_dir / name).is_symlink()]
            for filename in filenames:
                candidate = base_dir / filename
                if candidate.is_symlink():
                    continue
                if not fnmatch.fnmatch(candidate.name, str(rule["pattern"])):
                    continue

                candidate_path = str(candidate)
                if candidate_path in seen_paths:
                    continue
                try:
                    stat_result = candidate.stat()
                except OSError:
                    continue
                file_age_seconds = (
                    scan_time - datetime.fromtimestamp(stat_result.st_mtime, tz=UTC)
                ).total_seconds()
                if file_age_seconds < float(rule["min_age_seconds"]):
                    continue
                file_size_bytes = int(stat_result.st_size)
                if file_size_bytes < int(rule["min_size_bytes"]):
                    continue
                seen_paths.add(candidate_path)
                matches.append(
                    CleanupCandidate(
                        path=candidate_path,
                        size_bytes=file_size_bytes,
                        rule=rule,
                        dry_run=bool(rule["dry_run"]),
                    )
                )
    return matches


def _coerce_cleanup_rule(raw_rule: object, *, rule_index: int) -> dict[str, Any] | None:
    if not isinstance(raw_rule, dict):
        return None
    if not bool(raw_rule.get("enabled", False)):
        return None

    path = str(raw_rule.get("path", "")).strip()
    if not path:
        return None
    pattern = str(raw_rule.get("pattern", "*")).strip() or "*"
    min_age_days = _coerce_non_negative_float(raw_rule.get("min_age_days"))
    if min_age_days is None:
        return None
    min_size_mb = _coerce_non_negative_float(raw_rule.get("min_size_mb"))
    if min_size_mb is None:
        return None
    dry_run = bool(raw_rule.get("dry_run", False))

    min_age_seconds = min_age_days * 86400.0
    min_size_bytes = int(min_size_mb * 1024 * 1024)
    return {
        "index": rule_index,
        "path": path,
        "pattern": pattern,
        "min_age_days": min_age_days,
        "min_age_seconds": min_age_seconds,
        "min_size_mb": min_size_mb,
        "min_size_bytes": min_size_bytes,
        "enabled": True,
        "dry_run": dry_run,
    }


def _coerce_non_negative_float(raw: object) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
    elif isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            value = float(text)
        except ValueError:
            return None
    else:
        return None
    if value < 0:
        return None
    return value


def _format_bytes(value: int) -> str:
    size = float(value)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    display = f"{size:.1f}".rstrip("0").rstrip(".")
    return f"{display} {units[unit_index]}"


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
