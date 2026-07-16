from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

from system_sentinel.chat.maintenance_utils import build_storage_report

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
    assert "Top 2 subdirectories by size:" in report
    assert str(big) in report
    assert str(small) in report
