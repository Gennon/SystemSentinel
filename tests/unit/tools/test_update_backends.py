from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest

from system_sentinel.tools.update.backends import (
    AptBackend,
    DnfBackend,
    PacmanBackend,
    UnsupportedDistroError,
    detect_backend,
)

# ---------------------------------------------------------------------------
# detect_backend — /etc/os-release parsing
# ---------------------------------------------------------------------------


def _os_release(content: str) -> Any:
    return patch("builtins.open", mock_open(read_data=content))


def test_detect_ubuntu_returns_apt_backend() -> None:
    content = "ID=ubuntu\nID_LIKE=debian\n"
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, AptBackend)


def test_detect_debian_returns_apt_backend() -> None:
    content = "ID=debian\n"
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, AptBackend)


def test_detect_id_like_debian_returns_apt_backend() -> None:
    content = "ID=linuxmint\nID_LIKE=ubuntu debian\n"
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, AptBackend)


def test_detect_fedora_returns_dnf_backend() -> None:
    content = "ID=fedora\n"
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, DnfBackend)


def test_detect_rhel_returns_dnf_backend() -> None:
    content = "ID=rhel\nID_LIKE=fedora\n"
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, DnfBackend)


def test_detect_centos_returns_dnf_backend() -> None:
    content = 'ID="centos"\nID_LIKE="rhel fedora"\n'
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, DnfBackend)


def test_detect_rocky_returns_dnf_backend() -> None:
    content = 'ID="rocky"\nID_LIKE="rhel centos fedora"\n'
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, DnfBackend)


def test_detect_arch_returns_pacman_backend() -> None:
    content = "ID=arch\n"
    with _os_release(content):
        backend = detect_backend()
    assert isinstance(backend, PacmanBackend)


def test_detect_unknown_distro_raises() -> None:
    content = "ID=gentoo\n"
    with _os_release(content), pytest.raises(UnsupportedDistroError, match="gentoo"):
        detect_backend()


def test_detect_missing_os_release_raises() -> None:
    with (
        patch("builtins.open", side_effect=FileNotFoundError),
        pytest.raises(UnsupportedDistroError, match="/etc/os-release"),
    ):
        detect_backend()


# ---------------------------------------------------------------------------
# AptBackend
# ---------------------------------------------------------------------------


def _fake_proc(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0) -> MagicMock:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.returncode = returncode
    return proc


@pytest.mark.asyncio
async def test_apt_upgrade_invokes_unattended_upgrades() -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_exec(*args: str, **kwargs: Any) -> MagicMock:
        calls.append(args)
        return _fake_proc()

    with patch(
        "system_sentinel.tools.update.backends.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        await AptBackend().upgrade()

    assert any("unattended-upgrade" in a for tup in calls for a in tup)
    flat = " ".join(a for tup in calls for a in tup)
    assert "dist-upgrade" not in flat
    assert "full-upgrade" not in flat


@pytest.mark.asyncio
async def test_apt_dry_run_passes_dry_run_flag() -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_exec(*args: str, **kwargs: Any) -> MagicMock:
        calls.append(args)
        return _fake_proc()

    with patch(
        "system_sentinel.tools.update.backends.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        await AptBackend().upgrade(dry_run=True)

    flat = " ".join(a for tup in calls for a in tup)
    assert "--dry-run" in flat


@pytest.mark.asyncio
async def test_apt_reboot_required_checks_sentinel_file() -> None:
    with patch("system_sentinel.tools.update.backends.Path") as mock_path:
        mock_path.return_value.exists.return_value = True
        result = await AptBackend().reboot_required()
    assert result is True


@pytest.mark.asyncio
async def test_apt_no_reboot_when_file_absent() -> None:
    with patch("system_sentinel.tools.update.backends.Path") as mock_path:
        mock_path.return_value.exists.return_value = False
        result = await AptBackend().reboot_required()
    assert result is False


@pytest.mark.asyncio
async def test_apt_parses_upgraded_packages_from_output() -> None:
    stdout = b"Packages upgraded: curl openssh-server ufw\n"
    packages = AptBackend().parse_upgraded_packages(stdout)
    assert packages == ["curl", "openssh-server", "ufw"]


# ---------------------------------------------------------------------------
# DnfBackend
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dnf_upgrade_uses_security_flag() -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_exec(*args: str, **kwargs: Any) -> MagicMock:
        calls.append(args)
        return _fake_proc()

    with patch(
        "system_sentinel.tools.update.backends.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        await DnfBackend().upgrade()

    flat = " ".join(a for tup in calls for a in tup)
    assert "dnf" in flat
    assert "--security" in flat
    assert "dist-upgrade" not in flat


@pytest.mark.asyncio
async def test_dnf_dry_run_passes_dry_run_flag() -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_exec(*args: str, **kwargs: Any) -> MagicMock:
        calls.append(args)
        return _fake_proc()

    with patch(
        "system_sentinel.tools.update.backends.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        await DnfBackend().upgrade(dry_run=True)

    flat = " ".join(a for tup in calls for a in tup)
    assert "--dry-run" in flat or "--assumeno" in flat


@pytest.mark.asyncio
async def test_dnf_reboot_required_when_needs_restarting_exits_nonzero() -> None:
    with patch(
        "system_sentinel.tools.update.backends.asyncio.create_subprocess_exec",
        return_value=_fake_proc(returncode=1),
    ):
        result = await DnfBackend().reboot_required()
    assert result is True


@pytest.mark.asyncio
async def test_dnf_no_reboot_when_needs_restarting_exits_zero() -> None:
    with patch(
        "system_sentinel.tools.update.backends.asyncio.create_subprocess_exec",
        return_value=_fake_proc(returncode=0),
    ):
        result = await DnfBackend().reboot_required()
    assert result is False


@pytest.mark.asyncio
async def test_dnf_parses_upgraded_packages_from_output() -> None:
    stdout = b"Upgraded: curl-7.88 openssh-8.0\n"
    packages = DnfBackend().parse_upgraded_packages(stdout)
    assert "curl-7.88" in packages
    assert "openssh-8.0" in packages


# ---------------------------------------------------------------------------
# PacmanBackend — unsupported, raises on upgrade
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pacman_upgrade_raises_unsupported() -> None:
    with pytest.raises(UnsupportedDistroError, match=r"[Aa]rch"):
        await PacmanBackend().upgrade()


@pytest.mark.asyncio
async def test_pacman_dry_run_raises_unsupported() -> None:
    with pytest.raises(UnsupportedDistroError, match=r"[Aa]rch"):
        await PacmanBackend().upgrade(dry_run=True)
