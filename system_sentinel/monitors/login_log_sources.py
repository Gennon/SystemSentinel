from __future__ import annotations

import subprocess
from typing import Any

from system_sentinel.core.time_config import parse_duration_from_config


def read_journald_lines(*, config: dict[str, Any], logger: Any) -> list[str]:
    window_seconds = parse_duration_from_config(
        config,
        key="failed_login_window",
        default_seconds=10 * 60,
        logger=logger,
    )
    window_minutes = max(1, int(window_seconds // 60))
    result = subprocess.run(
        [
            "/usr/bin/journalctl",
            "--identifier=sshd",
            f"--since={window_minutes} minutes ago",
            "--no-pager",
            "--output=short",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"journalctl exited {result.returncode}: {result.stderr}")
    return result.stdout.splitlines()


def read_auth_log_lines(*, auth_log_path: str = "/var/log/auth.log") -> list[str]:
    with open(auth_log_path) as fh:
        return fh.readlines()
