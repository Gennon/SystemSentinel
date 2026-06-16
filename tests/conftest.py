from __future__ import annotations

import io

import pytest

from system_sentinel.setup.wizard import WizardContext


@pytest.fixture
def default_ctx() -> WizardContext:
    """A WizardContext with all flags at their defaults."""
    return WizardContext()


@pytest.fixture
def check_only_ctx() -> WizardContext:
    return WizardContext(check_only=True)


@pytest.fixture
def unattended_ctx() -> WizardContext:
    return WizardContext(unattended=True)


@pytest.fixture
def captured_output() -> io.StringIO:
    """A StringIO buffer for injecting into SetupWizard as the output stream."""
    return io.StringIO()
