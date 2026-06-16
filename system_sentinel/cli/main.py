from __future__ import annotations

import sys

import click

from system_sentinel.setup import build_wizard
from system_sentinel.setup.wizard import SetupWizard, WizardContext


@click.group()
def cli() -> None:
    """SystemSentinel — automated Linux system maintenance and monitoring."""


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

    if check_only:
        click.echo("Mode: check-only (no changes will be made)\n")

    ctx = WizardContext(
        check_only=check_only,
        unattended=unattended,
        enabled_features=list(enabled_features),
    )

    wizard = build_wizard()
    results = wizard.run(ctx)

    click.echo("")
    if SetupWizard.succeeded(results):
        click.echo("SystemSentinel is running.")
        click.echo('Tip: send "!status" in your chat channel to verify connectivity.')
        sys.exit(0)
    else:
        sys.exit(1)
