from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging

_DEFAULT_INTERVAL_SECONDS = 300
_MIN_INTERVAL_SECONDS = 30


class SelfUpdateError(RuntimeError):
    """Raised when a self-update check or apply step fails."""


@dataclass(frozen=True)
class SelfUpdateConfig:
    enabled: bool
    check_interval_seconds: int
    repository_path: Path | None
    remote: str
    branch: str
    reinstall: bool

    @classmethod
    def from_updates_config(cls, updates_cfg: dict[str, Any]) -> SelfUpdateConfig:
        raw_self_update = updates_cfg.get("self_update", {})
        self_update_cfg = raw_self_update if isinstance(raw_self_update, dict) else {}
        repo_value = self_update_cfg.get("source_path", self_update_cfg.get("repository_path"))
        repository_path = (
            Path(str(repo_value)).expanduser().resolve()
            if repo_value is not None
            else _discover_repository_path()
        )
        raw_interval = self_update_cfg.get("check_interval_seconds", _DEFAULT_INTERVAL_SECONDS)
        interval = max(_MIN_INTERVAL_SECONDS, int(raw_interval))
        return cls(
            enabled=bool(self_update_cfg.get("enabled", False)),
            check_interval_seconds=interval,
            repository_path=repository_path,
            remote=str(self_update_cfg.get("remote", "origin")),
            branch=str(self_update_cfg.get("branch", "main")),
            reinstall=bool(self_update_cfg.get("reinstall", True)),
        )


class SelfUpdateMonitor:
    def __init__(self, updates_cfg: dict[str, Any], logger: logging.Logger) -> None:
        self.config = SelfUpdateConfig.from_updates_config(updates_cfg)
        self._logger = logger.getChild("self_update")

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def check_interval_seconds(self) -> int:
        return self.config.check_interval_seconds

    async def check_and_apply_update(self) -> bool:
        if not self.enabled:
            return False
        repo_path = self.config.repository_path
        if repo_path is None:
            self._logger.warning(
                "Self-update is enabled but no update source path was detected. "
                "Set updates.self_update.repository_path in config.yaml."
            )
            return False

        fetch = await _run_command(
            "git", "-C", str(repo_path), "fetch", self.config.remote, self.config.branch
        )
        if fetch.returncode != 0:
            raise SelfUpdateError(
                "git fetch failed: "
                f"{fetch.stderr.decode(errors='replace').strip() or fetch.stdout.decode(errors='replace').strip()}"
            )

        local_head = await _git_rev_parse(repo_path, "HEAD")
        remote_head = await _git_rev_parse(repo_path, f"{self.config.remote}/{self.config.branch}")
        if local_head == remote_head:
            return False

        self._logger.info(
            "New update detected on %s/%s — applying self-update.",
            self.config.remote,
            self.config.branch,
        )
        pull = await _run_command(
            "git",
            "-C",
            str(repo_path),
            "pull",
            "--ff-only",
            self.config.remote,
            self.config.branch,
        )
        if pull.returncode != 0:
            raise SelfUpdateError(
                "git pull failed: "
                f"{pull.stderr.decode(errors='replace').strip() or pull.stdout.decode(errors='replace').strip()}"
            )

        if self.config.reinstall:
            await _reinstall_editable(repo_path)

        self._logger.info("Self-update applied successfully.")
        return True


@dataclass(frozen=True)
class _CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int


async def _run_command(*args: str) -> _CommandResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise SelfUpdateError(f"Command not found: {args[0]}") from exc
    stdout, stderr = await proc.communicate()
    return _CommandResult(stdout=stdout, stderr=stderr, returncode=proc.returncode or 0)


async def _git_rev_parse(repo_path: Path, ref: str) -> str:
    cmd = await _run_command("git", "-C", str(repo_path), "rev-parse", ref)
    if cmd.returncode != 0:
        raise SelfUpdateError(
            f"git rev-parse {ref!r} failed: "
            f"{cmd.stderr.decode(errors='replace').strip() or cmd.stdout.decode(errors='replace').strip()}"
        )
    return cmd.stdout.decode(errors="replace").strip()


async def _reinstall_editable(repo_path: Path) -> None:
    pip_bin = repo_path / ".venv" / "bin" / "pip"
    if not pip_bin.exists():
        return
    result = await _run_command(str(pip_bin), "install", "-e", str(repo_path))
    if result.returncode != 0:
        raise SelfUpdateError(
            "pip install -e failed after pull: "
            f"{result.stderr.decode(errors='replace').strip() or result.stdout.decode(errors='replace').strip()}"
        )


def _discover_repository_path() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        if (parent / ".git").exists():
            return parent
    return None
