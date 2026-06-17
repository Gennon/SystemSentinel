from __future__ import annotations

from system_sentinel.setup.dependency_installer import (
    check_platform_step,
    install_python_packages_step,
    install_system_packages_step,
)
from system_sentinel.setup.optional_features import (
    install_optional_features_step,
    select_features_step,
)
from system_sentinel.setup.systemd_installer import (
    create_sentinel_user_step,
    enable_systemd_service_step,
    install_systemd_service_step,
    start_systemd_service_step,
)
from system_sentinel.setup.wizard import SetupWizard, WizardStep


def build_wizard() -> SetupWizard:
    """Construct the canonical SetupWizard with all standard steps in order."""
    steps: list[WizardStep] = [
        check_platform_step(),
        install_system_packages_step(),
        install_python_packages_step(),
        select_features_step(),
        install_optional_features_step(),
        create_sentinel_user_step(),
        install_systemd_service_step(),
        enable_systemd_service_step(),
        start_systemd_service_step(),
    ]
    return SetupWizard(steps=steps)
