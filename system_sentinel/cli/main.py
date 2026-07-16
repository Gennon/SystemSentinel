from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import shutil
import sys
from typing import Any

import click
import yaml

from system_sentinel.core.daemon import DaemonRestartRequested, run_daemon
from system_sentinel.core.exceptions import ConfigError
from system_sentinel.core.time_config import parse_duration_from_config, parse_duration_hhmmss
from system_sentinel.dashboard import launch_dashboard
from system_sentinel.setup import build_wizard
from system_sentinel.setup.wizard import SetupWizard, WizardContext

_DEFAULT_CONFIG_PATH = Path("/etc/sentinel/config.yaml")
_DEFAULT_DB_PATH = Path("/var/lib/sentinel/sentinel.db")


@click.group()
def cli() -> None:
    """SystemSentinel — automated Linux system maintenance and monitoring."""


def _restart_exec_args() -> tuple[str, list[str]]:
    launcher = sys.argv[0] if sys.argv else ""
    if launcher:
        if os.path.isabs(launcher) and os.path.exists(launcher):
            return launcher, list(sys.argv)
        resolved = shutil.which(launcher)
        if resolved:
            return resolved, [resolved, *sys.argv[1:]]
    return sys.executable, [sys.executable, *sys.argv]


def _restart_current_process() -> None:
    executable, args = _restart_exec_args()
    os.execv(executable, args)


def _load_optional_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        return {}
    try:
        loaded = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse {config_path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"{config_path} must contain a YAML mapping, got {type(loaded).__name__}")
    return loaded


def _dashboard_refresh_interval(config: dict[str, Any]) -> float:
    dashboard_cfg_raw = config.get("dashboard", {})
    dashboard_cfg = dashboard_cfg_raw if isinstance(dashboard_cfg_raw, dict) else {}
    logger = logging.getLogger("sentinel.cli.dashboard")
    return parse_duration_from_config(
        dashboard_cfg,
        key="refresh_interval",
        default_seconds=5.0,
        logger=logger,
    )


@cli.command()
def run() -> None:
    """Start the SystemSentinel daemon.

    Loads /etc/sentinel/config.yaml, wires all components, and runs
    until SIGINT or SIGTERM is received. Intended to be called by
    the systemd service unit.
    """
    try:
        asyncio.run(run_daemon())
    except ConfigError as exc:
        click.echo(f"Configuration error: {exc}", err=True)
        sys.exit(1)
    except DaemonRestartRequested:
        try:
            _restart_current_process()
        except OSError as exc:
            click.echo(f"Failed to restart daemon process: {exc}", err=True)
            sys.exit(1)


@cli.command()
@click.option(
    "--check",
    "check_only",
    is_flag=True,
    default=False,
    help="Run checks only; make no changes to the system.",
)
@click.option(
    "--unattended",
    is_flag=True,
    default=False,
    help="Skip interactive prompts and apply defaults (for automated provisioning).",
)
@click.option(
    "--enable",
    "enabled_features",
    multiple=True,
    metavar="FEATURE",
    help="Enable an optional feature in unattended mode (repeatable).",
)
def setup(
    check_only: bool,
    unattended: bool,
    enabled_features: tuple[str, ...],
) -> None:
    """Run the first-time setup wizard.

    Installs dependencies, selects optional features, and configures the daemon.
    Re-running on an already-configured system is safe and idempotent.
    """
    click.echo("SystemSentinel Setup Wizard")
    click.echo("=" * 40)
    click.echo("This wizard will:")
    click.echo("  1. Validate your platform and install dependencies")
    click.echo("  2. Create a dedicated system user (sentinel)")
    click.echo("  3. Install and start the SystemSentinel daemon")

    if check_only:
        click.echo("\nMode: check-only (no changes will be made)")
    if unattended:
        click.echo("\nMode: unattended (applying defaults)")
    click.echo("")

    ctx = WizardContext(
        check_only=check_only,
        unattended=unattended,
        enabled_features=list(enabled_features),
    )

    wizard = build_wizard()
    results = wizard.run(ctx)

    click.echo("")
    click.echo("Setup Summary")
    click.echo("=" * 40)
    for result in results:
        icon = SetupWizard.STEP_ICON[result.outcome]
        click.echo(f"  {icon} {result.step_name}: {result.message}")

    click.echo("")
    if SetupWizard.succeeded(results):
        click.echo("SystemSentinel is running.")
        click.echo('Tip: send "!status" in your chat channel to verify connectivity.')
        sys.exit(0)
    else:
        sys.exit(1)


@cli.command()
@click.option(
    "--db-path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=_DEFAULT_DB_PATH,
    show_default=True,
    help="Path to the local SQLite database.",
)
@click.option(
    "--config-path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=_DEFAULT_CONFIG_PATH,
    show_default=True,
    help="Path to config.yaml (used for dashboard settings and alert thresholds).",
)
@click.option(
    "--refresh-interval",
    type=str,
    default=None,
    help="Refresh interval in HH:MM:SS (overrides config).",
)
def dashboard(db_path: Path, config_path: Path, refresh_interval: str | None) -> None:
    """Launch the terminal dashboard for local historical system status."""
    try:
        config = _load_optional_config(config_path)
    except ConfigError as exc:
        click.echo(f"Configuration error: {exc}", err=True)
        sys.exit(1)

    resolved_refresh = _dashboard_refresh_interval(config)
    if refresh_interval is not None:
        parsed = parse_duration_hhmmss(refresh_interval)
        if parsed is None:
            click.echo(
                "Invalid --refresh-interval value. Expected HH:MM:SS or <days>d HH:MM:SS.",
                err=True,
            )
            sys.exit(1)
        resolved_refresh = parsed[0]

    launch_dashboard(
        db_path=db_path,
        config=config,
        refresh_interval_seconds=max(0.25, resolved_refresh),
    )
