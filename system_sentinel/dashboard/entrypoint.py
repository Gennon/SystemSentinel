from __future__ import annotations

from system_sentinel.cli.main import (
    _DEFAULT_CONFIG_PATH,
    _DEFAULT_DB_PATH,
    _dashboard_refresh_interval,
    _load_optional_config,
)
from system_sentinel.dashboard.app import launch_dashboard


def main() -> None:
    config = _load_optional_config(_DEFAULT_CONFIG_PATH)
    launch_dashboard(
        db_path=_DEFAULT_DB_PATH,
        config=config,
        refresh_interval_seconds=_dashboard_refresh_interval(config),
    )
