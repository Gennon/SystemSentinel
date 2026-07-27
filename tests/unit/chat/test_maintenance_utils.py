from __future__ import annotations

from datetime import UTC, datetime, timedelta
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING

from system_sentinel.chat.maintenance_utils import build_storage_report, run_cleanup_rules

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_build_storage_report_includes_threshold_flag_and_top_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    big = root / "big"
    small = root / "small"
    big.mkdir()
    small.mkdir()
    (big / "a.bin").write_bytes(b"x" * 200)
    (small / "b.bin").write_bytes(b"x" * 10)

    monkeypatch.setattr(
        "system_sentinel.chat.maintenance_utils.psutil.disk_usage",
        lambda _path: SimpleNamespace(used=900, free=100, total=1000, percent=90.0),
    )

    report = build_storage_report([str(root)], disk_alert_threshold_percent=85.0)

    assert "status=ALERT" in report
    assert "used=900 B free=100 B total=1000 B" in report
    assert "Top 2 subdirectories by size:" in report
    assert f"- {big}: 200 B" in report
    assert f"- {small}: 10 B" in report
    assert str(big) in report
    assert str(small) in report


def test_run_cleanup_rules_respects_enabled_age_size_pattern_and_dry_run(tmp_path: Path) -> None:
    cleanup_root = tmp_path / "cleanup"
    cleanup_root.mkdir()
    old_large_log = cleanup_root / "old-large.log"
    old_large_log.write_bytes(b"x" * (2 * 1024 * 1024))
    old_small_log = cleanup_root / "old-small.log"
    old_small_log.write_bytes(b"x" * 100)
    old_other = cleanup_root / "old-large.txt"
    old_other.write_bytes(b"x" * (2 * 1024 * 1024))
    now = datetime.now(UTC)
    old_timestamp = (now - timedelta(days=2)).timestamp()
    os.utime(old_large_log, (old_timestamp, old_timestamp))
    os.utime(old_small_log, (old_timestamp, old_timestamp))
    os.utime(old_other, (old_timestamp, old_timestamp))

    matches = run_cleanup_rules(
        [
            {
                "enabled": True,
                "path": str(cleanup_root),
                "min_age_days": 1,
                "min_size_mb": 1,
                "pattern": "*.log",
                "dry_run": True,
            }
        ],
        now=now,
    )

    assert len(matches) == 1
    assert matches[0].path == str(old_large_log)
    assert matches[0].dry_run is True


def test_run_cleanup_rules_never_follows_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "target.log"
    outside_file.write_text("dont-follow")

    cleanup_root = tmp_path / "cleanup"
    cleanup_root.mkdir()
    linked_dir = cleanup_root / "linked"
    linked_dir.symlink_to(outside, target_is_directory=True)
    linked_file = cleanup_root / "linked-file.log"
    linked_file.symlink_to(outside_file)

    now = datetime.now(UTC)
    matches = run_cleanup_rules(
        [
            {
                "enabled": True,
                "path": str(cleanup_root),
                "min_age_days": 0,
                "min_size_mb": 0,
                "pattern": "*.log",
                "dry_run": False,
            }
        ],
        now=now,
    )

    assert matches == []
