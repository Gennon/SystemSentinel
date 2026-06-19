from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from pathlib import Path

_OS_RELEASE = "/etc/os-release"
_APT_REBOOT_FILE = "/var/run/reboot-required"
_DNF_BIN = "/usr/bin/dnf"
_UNATTENDED_UPGRADES_BIN = "/usr/bin/unattended-upgrades"
_APT_GET_BIN = "/usr/bin/apt-get"
_DPKG_QUERY_BIN = "/usr/bin/dpkg-query"
_NEEDS_RESTARTING_BIN = "/usr/bin/needs-restarting"
_RPM_BIN = "/usr/bin/rpm"
_PACMAN_BIN = "/usr/bin/pacman"


class UnsupportedDistroError(Exception):
    """Raised when the host distro has no supported security-update backend."""


class PackageBackend(ABC):
    @abstractmethod
    async def upgrade(self, *, dry_run: bool = False) -> tuple[bytes, bytes, int]:
        """Run security upgrades. Returns (stdout, stderr, returncode)."""
        ...

    @abstractmethod
    async def reboot_required(self) -> bool:
        """Return True if a reboot is needed to complete pending updates."""
        ...

    @abstractmethod
    def parse_upgraded_packages(self, stdout: bytes) -> list[str]:
        """Extract a list of upgraded package names from upgrade stdout."""
        ...

    @abstractmethod
    async def is_installed(self, package: str) -> bool:
        """Return True if the package is currently installed."""
        ...

    @abstractmethod
    async def install(self, package: str) -> tuple[bytes, bytes, int]:
        """Install a package. Returns (stdout, stderr, returncode)."""
        ...


class AptBackend(PackageBackend):
    async def upgrade(self, *, dry_run: bool = False) -> tuple[bytes, bytes, int]:
        args = [_UNATTENDED_UPGRADES_BIN, "--verbose"]
        if dry_run:
            args.append("--dry-run")
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout, stderr, proc.returncode or 0

    async def reboot_required(self) -> bool:
        return Path(_APT_REBOOT_FILE).exists()

    def parse_upgraded_packages(self, stdout: bytes) -> list[str]:
        packages: list[str] = []
        for line in stdout.decode(errors="replace").splitlines():
            low = line.lower()
            if "upgraded:" in low or "packages upgraded:" in low:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    packages.extend(p.strip() for p in parts[1].split() if p.strip())
        return packages

    async def is_installed(self, package: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            _DPKG_QUERY_BIN,
            "-W",
            "-f=${Status}",
            package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return b"install ok installed" in stdout

    async def install(self, package: str) -> tuple[bytes, bytes, int]:
        proc = await asyncio.create_subprocess_exec(
            "sudo",
            _APT_GET_BIN,
            "install",
            "-y",
            package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout, stderr, proc.returncode or 0


class DnfBackend(PackageBackend):
    async def upgrade(self, *, dry_run: bool = False) -> tuple[bytes, bytes, int]:
        args = ["sudo", _DNF_BIN, "upgrade", "--security", "-y"]
        if dry_run:
            args.append("--dry-run")
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout, stderr, proc.returncode or 0

    async def reboot_required(self) -> bool:
        # needs-restarting -r exits 1 when a reboot is required, 0 when not
        try:
            proc = await asyncio.create_subprocess_exec(
                _NEEDS_RESTARTING_BIN,
                "-r",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return (proc.returncode or 0) != 0
        except FileNotFoundError:
            return False

    def parse_upgraded_packages(self, stdout: bytes) -> list[str]:
        packages: list[str] = []
        for line in stdout.decode(errors="replace").splitlines():
            low = line.lower()
            if low.startswith("upgraded:") or low.startswith("installing:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    packages.extend(p.strip() for p in parts[1].split() if p.strip())
        return packages

    async def is_installed(self, package: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            _RPM_BIN,
            "-q",
            package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return (proc.returncode or 0) == 0

    async def install(self, package: str) -> tuple[bytes, bytes, int]:
        proc = await asyncio.create_subprocess_exec(
            "sudo",
            _DNF_BIN,
            "install",
            "-y",
            package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout, stderr, proc.returncode or 0


class PacmanBackend(PackageBackend):
    async def upgrade(self, *, dry_run: bool = False) -> tuple[bytes, bytes, int]:
        raise UnsupportedDistroError(
            "Arch Linux does not support security-only updates. "
            "Use `pacman -Syu` manually to apply all updates."
        )

    async def reboot_required(self) -> bool:
        return False

    def parse_upgraded_packages(self, stdout: bytes) -> list[str]:
        return []

    async def is_installed(self, package: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            _PACMAN_BIN,
            "-Q",
            package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return (proc.returncode or 0) == 0

    async def install(self, package: str) -> tuple[bytes, bytes, int]:
        proc = await asyncio.create_subprocess_exec(
            "sudo",
            _PACMAN_BIN,
            "-S",
            "--noconfirm",
            package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return stdout, stderr, proc.returncode or 0


def _parse_os_release(path: str = _OS_RELEASE) -> dict[str, str]:
    fields: dict[str, str] = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')
    return fields


def detect_backend() -> PackageBackend:
    """Detect the host distro and return the appropriate PackageBackend."""
    try:
        fields = _parse_os_release()
    except FileNotFoundError as exc:
        raise UnsupportedDistroError(
            "/etc/os-release not found — cannot detect Linux distribution."
        ) from exc

    distro_id = fields.get("ID", "").lower()
    id_like = fields.get("ID_LIKE", "").lower().split()

    all_ids = {distro_id} | set(id_like)

    if all_ids & {"debian", "ubuntu"}:
        return AptBackend()
    if all_ids & {"fedora", "rhel", "centos", "rocky", "almalinux"}:
        return DnfBackend()
    if distro_id == "arch":
        return PacmanBackend()

    raise UnsupportedDistroError(
        f"Unsupported Linux distribution: {distro_id!r}. "
        "Supported: Debian/Ubuntu (apt), RHEL/Fedora/CentOS/Rocky (dnf)."
    )
