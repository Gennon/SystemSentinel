from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
import re
import shutil
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging

    from system_sentinel.core.context import AuditRepository

_DEFAULT_KEEP_LAST = 20
_SNAPSHOT_LABEL_PREFIX = "system-sentinel"
_SUPPORTED_BACKENDS = ("snapper", "timeshift")


class SnapshotError(RuntimeError):
    """Raised when snapshot create/list/delete operations fail."""


@dataclass(frozen=True)
class SnapshotRecord:
    backend: str
    snapshot_id: str
    created_at: str
    label: str


class SnapshotBackend:
    name: str

    async def create(self, label: str) -> SnapshotRecord:
        raise NotImplementedError

    async def list_recent(self, *, limit: int) -> list[SnapshotRecord]:
        raise NotImplementedError

    async def delete(self, snapshot_id: str) -> None:
        raise NotImplementedError


class SnapshotManager:
    def __init__(
        self,
        *,
        backend: SnapshotBackend | None,
        keep_last: int,
        audit: AuditRepository,
        logger: logging.Logger,
    ) -> None:
        self._backend = backend
        self._keep_last = max(0, keep_last)
        self._audit = audit
        self._logger = logger.getChild("snapshots")

    @property
    def enabled(self) -> bool:
        return self._backend is not None

    @classmethod
    def from_config(
        cls,
        *,
        self_update_cfg: dict[str, Any],
        audit: AuditRepository,
        logger: logging.Logger,
    ) -> SnapshotManager:
        snapshots_cfg = self_update_cfg.get("snapshots", {})
        snapshots_data = snapshots_cfg if isinstance(snapshots_cfg, dict) else {}
        backend_name = str(snapshots_data.get("backend", "auto")).strip().lower() or "auto"
        keep_last = _coerce_keep_last(snapshots_data.get("keep_last"), logger=logger)

        if backend_name in {"none", "disabled"}:
            return cls(backend=None, keep_last=keep_last, audit=audit, logger=logger)

        backend = _select_backend(backend_name)
        if backend is None:
            logger.warning(
                "Snapshot backend is configured as %r but no supported tool is available; "
                "self-update will continue without snapshots.",
                backend_name,
            )
            return cls(backend=None, keep_last=keep_last, audit=audit, logger=logger)
        return cls(backend=backend, keep_last=keep_last, audit=audit, logger=logger)

    async def create_snapshot(self, label: str) -> SnapshotRecord:
        backend = self._backend
        if backend is None:
            raise SnapshotError("Snapshot backend is not available.")

        try:
            snapshot = await backend.create(label)
        except SnapshotError as exc:
            await self._record_create_failure(backend.name, label, str(exc))
            raise

        await self._audit.append(
            action_type="snapshot_create",
            source="self_update",
            description=f"{backend.name} snapshot created.",
            outcome="success",
            details={
                "snapshot_id": snapshot.snapshot_id,
                "label": snapshot.label,
                "backend": snapshot.backend,
                "created_at": snapshot.created_at,
            },
        )
        await self._prune_snapshots()
        return snapshot

    async def _prune_snapshots(self) -> None:
        backend = self._backend
        if backend is None or self._keep_last <= 0:
            return
        snapshots = await backend.list_recent(limit=self._keep_last + 20)
        if len(snapshots) <= self._keep_last:
            return

        for snapshot in snapshots[self._keep_last :]:
            try:
                await backend.delete(snapshot.snapshot_id)
            except SnapshotError as exc:
                await self._audit.append(
                    action_type="snapshot_delete",
                    source="self_update",
                    description=f"{backend.name} snapshot deletion failed.",
                    outcome="failure",
                    details={
                        "snapshot_id": snapshot.snapshot_id,
                        "label": snapshot.label,
                        "backend": snapshot.backend,
                        "error": str(exc),
                    },
                )
                continue
            await self._audit.append(
                action_type="snapshot_delete",
                source="self_update",
                description=f"{backend.name} snapshot deleted.",
                outcome="success",
                details={
                    "snapshot_id": snapshot.snapshot_id,
                    "label": snapshot.label,
                    "backend": snapshot.backend,
                    "created_at": snapshot.created_at,
                },
            )

    async def _record_create_failure(self, backend_name: str, label: str, error: str) -> None:
        await self._audit.append(
            action_type="snapshot_create",
            source="self_update",
            description=f"{backend_name} snapshot creation failed.",
            outcome="failure",
            details={"label": label, "backend": backend_name, "error": error},
        )


class SnapperBackend(SnapshotBackend):
    name = "snapper"

    async def create(self, label: str) -> SnapshotRecord:
        result = await _run_command(
            "snapper",
            "create",
            "--description",
            label,
            "--print-number",
        )
        if result.returncode != 0:
            raise SnapshotError(_error_text(result))
        output_lines = result.stdout.decode(errors="replace").strip().splitlines()
        snapshot_id = output_lines[-1] if output_lines else ""
        created_at = datetime.now(UTC).isoformat()
        if not snapshot_id:
            snapshot_id = created_at
        return SnapshotRecord(
            backend=self.name,
            snapshot_id=snapshot_id,
            created_at=created_at,
            label=label,
        )

    async def list_recent(self, *, limit: int) -> list[SnapshotRecord]:
        result = await _run_command(
            "snapper",
            "list",
            "--columns",
            "number,date,description",
            "--separator",
            "|",
        )
        if result.returncode != 0:
            raise SnapshotError(_error_text(result))

        rows: list[SnapshotRecord] = []
        for line in result.stdout.decode(errors="replace").splitlines():
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 3:
                continue
            if not parts[0].isdigit():
                continue
            rows.append(
                SnapshotRecord(
                    backend=self.name,
                    snapshot_id=parts[0],
                    created_at=parts[1],
                    label=parts[2],
                )
            )
        rows.reverse()
        return rows[:limit]

    async def delete(self, snapshot_id: str) -> None:
        result = await _run_command("snapper", "delete", snapshot_id)
        if result.returncode != 0:
            raise SnapshotError(_error_text(result))


class TimeshiftBackend(SnapshotBackend):
    name = "timeshift"

    async def create(self, label: str) -> SnapshotRecord:
        result = await _run_command("timeshift", "--create", "--comments", label, "--scripted")
        if result.returncode != 0:
            raise SnapshotError(_error_text(result))
        recent = await self.list_recent(limit=1)
        if recent:
            return recent[0]
        created_at = datetime.now(UTC).isoformat()
        return SnapshotRecord(
            backend=self.name,
            snapshot_id=created_at,
            created_at=created_at,
            label=label,
        )

    async def list_recent(self, *, limit: int) -> list[SnapshotRecord]:
        result = await _run_command("timeshift", "--list")
        if result.returncode != 0:
            raise SnapshotError(_error_text(result))
        rows: list[SnapshotRecord] = []
        for line in result.stdout.decode(errors="replace").splitlines():
            parsed = _parse_timeshift_line(line)
            if parsed is None:
                continue
            rows.append(parsed)
        rows.reverse()
        return rows[:limit]

    async def delete(self, snapshot_id: str) -> None:
        result = await _run_command(
            "timeshift", "--delete", "--snapshot", snapshot_id, "--scripted"
        )
        if result.returncode != 0:
            raise SnapshotError(_error_text(result))


@dataclass(frozen=True)
class _CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int


def _select_backend(backend_name: str) -> SnapshotBackend | None:
    if backend_name == "auto":
        for name in _SUPPORTED_BACKENDS:
            if shutil.which(name) is not None:
                return _backend_from_name(name)
        return None
    if shutil.which(backend_name) is None:
        return None
    return _backend_from_name(backend_name)


def _backend_from_name(name: str) -> SnapshotBackend:
    if name == "snapper":
        return SnapperBackend()
    if name == "timeshift":
        return TimeshiftBackend()
    raise SnapshotError(f"Unsupported snapshot backend: {name}")


def _parse_timeshift_line(line: str) -> SnapshotRecord | None:
    raw = line.strip()
    if not raw:
        return None
    if raw.startswith("Device") or raw.startswith("Num"):
        return None

    timestamp_match = re.search(r"\d{4}-\d{2}-\d{2}[_ ]\d{2}[-:]\d{2}[-:]\d{2}", raw)
    if timestamp_match is None:
        return None
    snapshot_id = timestamp_match.group(0)
    normalized = snapshot_id.replace("_", " ")
    label = raw.split(snapshot_id, 1)[-1].strip() or f"{_SNAPSHOT_LABEL_PREFIX} snapshot"
    return SnapshotRecord(
        backend="timeshift",
        snapshot_id=snapshot_id,
        created_at=normalized,
        label=label,
    )


def _error_text(result: _CommandResult) -> str:
    return (
        result.stderr.decode(errors="replace").strip()
        or result.stdout.decode(errors="replace").strip()
        or "unknown snapshot backend failure"
    )


async def _run_command(*args: str) -> _CommandResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise SnapshotError(f"Command not found: {args[0]}") from exc
    stdout, stderr = await proc.communicate()
    return _CommandResult(stdout=stdout, stderr=stderr, returncode=proc.returncode or 0)


def _coerce_keep_last(raw_value: object, *, logger: logging.Logger) -> int:
    if raw_value is None:
        return _DEFAULT_KEEP_LAST
    if isinstance(raw_value, bool):
        logger.warning(
            "Invalid snapshots.keep_last value %r; expected integer. Using default %d.",
            raw_value,
            _DEFAULT_KEEP_LAST,
        )
        return _DEFAULT_KEEP_LAST
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, float):
        return int(raw_value)
    if isinstance(raw_value, str):
        value = raw_value.strip()
        if not value:
            return _DEFAULT_KEEP_LAST
        try:
            return int(value)
        except ValueError:
            logger.warning(
                "Invalid snapshots.keep_last value %r; expected integer. Using default %d.",
                raw_value,
                _DEFAULT_KEEP_LAST,
            )
            return _DEFAULT_KEEP_LAST
    logger.warning(
        "Invalid snapshots.keep_last value type %s; using default %d.",
        type(raw_value).__name__,
        _DEFAULT_KEEP_LAST,
    )
    return _DEFAULT_KEEP_LAST
