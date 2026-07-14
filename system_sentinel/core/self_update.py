from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from system_sentinel.core.snapshots import SnapshotError
from system_sentinel.core.time_config import parse_duration_from_config

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    import logging

    from system_sentinel.core.snapshots import SnapshotManager

_DEFAULT_INTERVAL_SECONDS = 300
_MIN_INTERVAL_SECONDS = 30


class SelfUpdateError(RuntimeError):
    """Raised when a self-update check or apply step fails."""


@dataclass(frozen=True)
class SelfUpdateConfig:
    enabled: bool
    check_interval_seconds: int
    source_path: Path | None
    remote: str
    branch: str
    reinstall: bool

    @classmethod
    def from_updates_config(
        cls, updates_cfg: dict[str, Any], logger: logging.Logger
    ) -> SelfUpdateConfig:
        raw_self_update = updates_cfg.get("self_update", {})
        self_update_cfg = raw_self_update if isinstance(raw_self_update, dict) else {}
        repo_value = self_update_cfg.get("source_path")
        source_path = (
            Path(str(repo_value)).expanduser().resolve()
            if repo_value is not None
            else _discover_source_path()
        )
        interval = max(
            _MIN_INTERVAL_SECONDS,
            int(
                parse_duration_from_config(
                    self_update_cfg,
                    key="check_interval",
                    default_seconds=_DEFAULT_INTERVAL_SECONDS,
                    logger=logger.getChild("config"),
                )
            ),
        )
        return cls(
            enabled=bool(self_update_cfg.get("enabled", False)),
            check_interval_seconds=interval,
            source_path=source_path,
            remote=str(self_update_cfg.get("remote", "origin")),
            branch=str(self_update_cfg.get("branch", "main")),
            reinstall=bool(self_update_cfg.get("reinstall", True)),
        )


class SelfUpdateMonitor:
    def __init__(
        self,
        updates_cfg: dict[str, Any],
        logger: logging.Logger,
        on_update_start: Callable[[str, str], Awaitable[None]] | None = None,
        snapshot_manager: SnapshotManager | None = None,
        on_snapshot_warning: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._logger = logger.getChild("self_update")
        self.config = SelfUpdateConfig.from_updates_config(updates_cfg, self._logger)
        self._on_update_start = on_update_start
        self._snapshot_manager = snapshot_manager
        self._on_snapshot_warning = on_snapshot_warning

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def check_interval_seconds(self) -> int:
        return self.config.check_interval_seconds

    async def check_and_apply_update(self) -> bool:
        if not self.enabled:
            return False
        repo_path = self.config.source_path
        if repo_path is None:
            self._logger.warning(
                "Self-update is enabled but no update source path was detected. "
                "Set updates.self_update.source_path in config.yaml."
            )
            return False

        fetch = await _run_fetch(repo_path, self.config.remote, self.config.branch)
        if fetch.returncode != 0:
            if _has_dubious_ownership_error(fetch):
                await _mark_git_safe_directory(repo_path)
                fetch = await _run_fetch(repo_path, self.config.remote, self.config.branch)
            if fetch.returncode != 0:
                raise SelfUpdateError(
                    "git fetch failed: "
                    f"{fetch.stderr.decode(errors='replace').strip() or fetch.stdout.decode(errors='replace').strip()}"
                )

        local_head = await _git_rev_parse(repo_path, "HEAD")
        remote_head = await _git_rev_parse(repo_path, f"{self.config.remote}/{self.config.branch}")
        if local_head == remote_head:
            return False

        if self._snapshot_manager is not None and self._snapshot_manager.enabled:
            pre_label = (
                f"pre-update {self.config.remote}/{self.config.branch} "
                f"{datetime.now(UTC).isoformat()}"
            )
            try:
                await self._snapshot_manager.create_snapshot(pre_label)
            except SnapshotError as exc:
                warning = f"Skipping self-update because pre-update snapshot creation failed: {exc}"
                self._logger.warning(warning)
                if self._on_snapshot_warning is not None:
                    await self._on_snapshot_warning(warning)
                return False

        if self._on_update_start is not None:
            await self._on_update_start(self.config.remote, self.config.branch)

        self._logger.info(
            "New update detected on %s/%s — applying self-update.",
            self.config.remote,
            self.config.branch,
        )
        pull = await _run_command(
            "git",
            "-c",
            f"safe.directory={repo_path}",
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

        if self._snapshot_manager is not None and self._snapshot_manager.enabled:
            post_label = (
                f"post-update {self.config.remote}/{self.config.branch} "
                f"{datetime.now(UTC).isoformat()}"
            )
            try:
                await self._snapshot_manager.create_snapshot(post_label)
            except SnapshotError as exc:
                warning = f"Post-update snapshot creation failed: {exc}"
                self._logger.warning(warning)
                if self._on_snapshot_warning is not None:
                    await self._on_snapshot_warning(warning)

        self._logger.info("Self-update applied successfully.")
        return True


@dataclass(frozen=True)
class _CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int


async def _run_command(*args: str, env: dict[str, str] | None = None) -> _CommandResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError as exc:
        raise SelfUpdateError(f"Command not found: {args[0]}") from exc
    stdout, stderr = await proc.communicate()
    return _CommandResult(stdout=stdout, stderr=stderr, returncode=proc.returncode or 0)


async def _run_fetch(repo_path: Path, remote: str, branch: str) -> _CommandResult:
    return await _run_command(
        "git",
        "-c",
        f"safe.directory={repo_path}",
        "-C",
        str(repo_path),
        "fetch",
        remote,
        branch,
    )


def _has_dubious_ownership_error(result: _CommandResult) -> bool:
    msg = (
        f"{result.stderr.decode(errors='replace')} {result.stdout.decode(errors='replace')}".lower()
    )
    return "detected dubious ownership" in msg


async def _mark_git_safe_directory(repo_path: Path) -> None:
    home_dir = _effective_home_dir()
    home_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["HOME"] = str(home_dir)
    result = await _run_command(
        "git",
        "config",
        "--global",
        "--add",
        "safe.directory",
        str(repo_path),
        env=env,
    )
    if result.returncode != 0:
        raise SelfUpdateError(
            "git config safe.directory failed: "
            f"{result.stderr.decode(errors='replace').strip() or result.stdout.decode(errors='replace').strip()}"
        )


def _effective_home_dir() -> Path:
    current = os.environ.get("HOME")
    if current:
        return Path(current)
    return Path("/var/lib/sentinel")


async def _git_rev_parse(repo_path: Path, ref: str) -> str:
    cmd = await _run_command(
        "git",
        "-c",
        f"safe.directory={repo_path}",
        "-C",
        str(repo_path),
        "rev-parse",
        ref,
    )
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


def _discover_source_path() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        if (parent / ".git").exists():
            return parent
    return None
