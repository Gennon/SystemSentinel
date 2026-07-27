from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import pwd
from typing import TYPE_CHECKING, Any, Protocol

from system_sentinel.core.time_config import parse_duration_hhmmss
from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext

_DEFAULT_SCHEDULE = "7d 00:00:00"
_NOLOGIN_SHELL_SUFFIXES = (
    "/false",
    "/nologin",
    "/sync",
    "/shutdown",
    "/halt",
)
_SSHD_CONFIG_PATH = Path("/etc/ssh/sshd_config")
_SSHD_CONFIG_DIR = Path("/etc/ssh/sshd_config.d")
_PAM_SSHD_PATH = Path("/etc/pam.d/sshd")


@dataclass(frozen=True)
class AccountAuditStatus:
    username: str
    status: str
    reason: str
    methods: list[str]
    is_exempt: bool = False


@dataclass(frozen=True)
class TwoFactorAuditSnapshot:
    audited_at: datetime
    accounts: list[AccountAuditStatus]
    inspector_notes: list[str]


class TwoFactorInspector(Protocol):
    async def audit(self, *, exempt_accounts: set[str]) -> TwoFactorAuditSnapshot: ...


@dataclass(frozen=True)
class _SshAuthSignals:
    key_only_enforced: bool
    has_match_blocks: bool
    has_custom_auth_mechanism: bool
    has_read_error: bool
    notes: list[str]


@dataclass(frozen=True)
class _PamSignals:
    has_google_authenticator_module: bool
    has_read_error: bool
    notes: list[str]


class LocalTwoFactorInspector:
    async def audit(self, *, exempt_accounts: set[str]) -> TwoFactorAuditSnapshot:
        return await asyncio.to_thread(self._audit_sync, exempt_accounts)

    def _audit_sync(self, exempt_accounts: set[str]) -> TwoFactorAuditSnapshot:
        accounts: list[AccountAuditStatus] = []
        notes: list[str] = []
        ssh_signals = self._read_ssh_signals()
        pam_signals = self._read_pam_signals()
        notes.extend(ssh_signals.notes)
        notes.extend(pam_signals.notes)

        for entry in pwd.getpwall():
            username = entry.pw_name.strip()
            if not username:
                continue
            if self._is_system_or_non_login_account(entry):
                continue
            if username in exempt_accounts:
                accounts.append(
                    AccountAuditStatus(
                        username=username,
                        status="exempt",
                        reason="Configured as exempt account.",
                        methods=[],
                        is_exempt=True,
                    )
                )
                continue

            status = self._audit_single_account(
                username=username,
                home_dir=entry.pw_dir,
                ssh_signals=ssh_signals,
                pam_signals=pam_signals,
            )
            accounts.append(status)

        return TwoFactorAuditSnapshot(
            audited_at=datetime.now(UTC),
            accounts=accounts,
            inspector_notes=notes,
        )

    def _is_system_or_non_login_account(self, entry: pwd.struct_passwd) -> bool:
        if entry.pw_uid < 1000 and entry.pw_uid != 0:
            return True
        shell = str(entry.pw_shell or "").strip().lower()
        if not shell:
            return True
        return shell.endswith(_NOLOGIN_SHELL_SUFFIXES)

    def _audit_single_account(
        self,
        *,
        username: str,
        home_dir: str,
        ssh_signals: _SshAuthSignals,
        pam_signals: _PamSignals,
    ) -> AccountAuditStatus:
        methods: list[str] = []

        totp_present, totp_note = self._has_google_authenticator_secret(home_dir)
        if totp_present is True:
            methods.append("totp_google_authenticator")
        if totp_present is None:
            return AccountAuditStatus(
                username=username,
                status="unknown",
                reason=totp_note or "Unable to determine TOTP secret status.",
                methods=methods,
            )

        if ssh_signals.key_only_enforced:
            has_authorized_keys, key_note = self._has_ssh_authorized_keys(home_dir)
            if has_authorized_keys is True:
                methods.append("ssh_publickey_only")
            elif has_authorized_keys is None:
                return AccountAuditStatus(
                    username=username,
                    status="unknown",
                    reason=key_note or "Unable to determine SSH key status.",
                    methods=methods,
                )

        if methods:
            return AccountAuditStatus(
                username=username,
                status="pass",
                reason=f"Detected 2FA-compatible method(s): {', '.join(methods)}.",
                methods=methods,
            )

        if ssh_signals.has_match_blocks:
            return AccountAuditStatus(
                username=username,
                status="unknown",
                reason="sshd_config contains Match blocks; per-account auth policy is ambiguous.",
                methods=[],
            )
        if ssh_signals.has_custom_auth_mechanism:
            return AccountAuditStatus(
                username=username,
                status="unknown",
                reason="Custom SSH AuthenticationMethods configured; status cannot be inferred reliably.",
                methods=[],
            )
        if ssh_signals.has_read_error or pam_signals.has_read_error:
            return AccountAuditStatus(
                username=username,
                status="unknown",
                reason="Authentication configuration could not be fully read.",
                methods=[],
            )
        if pam_signals.has_google_authenticator_module:
            return AccountAuditStatus(
                username=username,
                status="unknown",
                reason=(
                    "Google Authenticator PAM module is present but no per-user TOTP secret "
                    "was detected."
                ),
                methods=[],
            )
        return AccountAuditStatus(
            username=username,
            status="fail",
            reason="No configured TOTP secret or SSH key-only enforcement detected.",
            methods=[],
        )

    def _has_google_authenticator_secret(self, home_dir: str) -> tuple[bool | None, str | None]:
        if not home_dir.strip():
            return False, None
        secret_path = Path(home_dir).expanduser() / ".google_authenticator"
        try:
            if not secret_path.exists() or not secret_path.is_file():
                return False, None
            return secret_path.stat().st_size > 0, None
        except PermissionError:
            return None, f"Permission denied while checking {secret_path}."
        except OSError as exc:
            return None, f"Unable to inspect {secret_path}: {exc}."

    def _has_ssh_authorized_keys(self, home_dir: str) -> tuple[bool | None, str | None]:
        if not home_dir.strip():
            return False, None
        key_path = Path(home_dir).expanduser() / ".ssh" / "authorized_keys"
        try:
            if not key_path.exists() or not key_path.is_file():
                return False, None
            return key_path.stat().st_size > 0, None
        except PermissionError:
            return None, f"Permission denied while checking {key_path}."
        except OSError as exc:
            return None, f"Unable to inspect {key_path}: {exc}."

    def _read_ssh_signals(self) -> _SshAuthSignals:
        lines: list[str] = []
        notes: list[str] = []
        read_error = False
        for path in [_SSHD_CONFIG_PATH, *_SSHD_CONFIG_DIR.glob("*.conf")]:
            if not path.exists():
                continue
            try:
                lines.extend(path.read_text().splitlines())
            except PermissionError:
                read_error = True
                notes.append(f"Permission denied while reading {path}.")
            except OSError as exc:
                read_error = True
                notes.append(f"Unable to read {path}: {exc}.")

        directives: dict[str, list[str]] = {}
        has_match_blocks = False
        for raw_line in lines:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if not parts:
                continue
            key = parts[0].lower()
            if key == "match":
                has_match_blocks = True
                continue
            if len(parts) == 1:
                continue
            directives[key] = parts[1:]

        pubkey_enabled = self._to_bool(directives.get("pubkeyauthentication"), default=True)
        password_enabled = (
            self._to_bool(directives.get("passwordauthentication"), default=True)
            or self._to_bool(directives.get("kbdinteractiveauthentication"), default=False)
            or self._to_bool(directives.get("challengeresponseauthentication"), default=False)
        )
        auth_methods = directives.get("authenticationmethods", [])
        normalized_methods = [value.strip().lower() for value in auth_methods if value.strip()]
        has_custom_auth = any(
            method != "publickey" and "," in method for method in normalized_methods
        ) or any("keyboard-interactive" in method for method in normalized_methods)
        key_only_enforced = pubkey_enabled and (not password_enabled) and not normalized_methods

        return _SshAuthSignals(
            key_only_enforced=key_only_enforced,
            has_match_blocks=has_match_blocks,
            has_custom_auth_mechanism=has_custom_auth,
            has_read_error=read_error,
            notes=notes,
        )

    def _read_pam_signals(self) -> _PamSignals:
        notes: list[str] = []
        if not _PAM_SSHD_PATH.exists():
            return _PamSignals(
                has_google_authenticator_module=False,
                has_read_error=False,
                notes=notes,
            )
        try:
            lines = _PAM_SSHD_PATH.read_text().splitlines()
        except PermissionError:
            return _PamSignals(
                has_google_authenticator_module=False,
                has_read_error=True,
                notes=[f"Permission denied while reading {_PAM_SSHD_PATH}."],
            )
        except OSError as exc:
            return _PamSignals(
                has_google_authenticator_module=False,
                has_read_error=True,
                notes=[f"Unable to read {_PAM_SSHD_PATH}: {exc}."],
            )

        has_module = any(
            "pam_google_authenticator.so" in line and not line.strip().startswith("#")
            for line in lines
        )
        if has_module:
            notes.append("Detected pam_google_authenticator.so in PAM SSH stack.")
        return _PamSignals(
            has_google_authenticator_module=has_module,
            has_read_error=False,
            notes=notes,
        )

    def _to_bool(self, values: list[str] | None, *, default: bool) -> bool:
        if not values:
            return default
        raw = values[-1].strip().lower()
        if raw in {"yes", "true", "on", "1"}:
            return True
        if raw in {"no", "false", "off", "0"}:
            return False
        return default


class TwoFactorAuditTool(BaseTool):
    name = "twofa_audit"
    display_name = "2FA Enforcement Audit"
    description = "Audits local user accounts for 2FA enforcement posture."

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        *,
        inspector: TwoFactorInspector | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self.config.setdefault("run_on_startup", False)
        self._inspector = inspector or LocalTwoFactorInspector()

    def schedule(self) -> str | None:
        raw = self.config.get("schedule")
        if raw is None:
            return _DEFAULT_SCHEDULE
        parsed = parse_duration_hhmmss(raw)
        if parsed is None or parsed[0] <= 0:
            self.ctx.logger.getChild("tool.twofa_audit").warning(
                "Invalid 2FA audit schedule %r; expected HH:MM:SS or <days>d HH:MM:SS. "
                "Using default %s.",
                raw,
                _DEFAULT_SCHEDULE,
            )
            return _DEFAULT_SCHEDULE
        return str(raw)

    async def run(self) -> ToolResult:
        started_at = datetime.now(UTC)
        if not self.is_enabled():
            return ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.SKIPPED,
                summary="2FA audit tool is disabled.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        db = self.ctx.db
        if db is None:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="2FA audit persistence unavailable: database not configured.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                details={"tool": self.name},
            )
            await self._record(result)
            return result

        exempt_accounts = self._exempt_accounts()
        snapshot = await self._inspector.audit(exempt_accounts=exempt_accounts)
        run_id = await self._persist_snapshot(snapshot, exempt_accounts=exempt_accounts)

        non_exempt_accounts = [account for account in snapshot.accounts if not account.is_exempt]
        pass_count = sum(1 for account in non_exempt_accounts if account.status == "pass")
        fail_accounts = [a.username for a in non_exempt_accounts if a.status == "fail"]
        unknown_accounts = [a.username for a in non_exempt_accounts if a.status == "unknown"]
        exempt_count = sum(1 for account in snapshot.accounts if account.is_exempt)

        result = ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary=(
                "2FA audit completed. "
                f"pass={pass_count}, fail={len(fail_accounts)}, unknown={len(unknown_accounts)}, "
                f"exempt={exempt_count}."
            ),
            started_at=started_at,
            finished_at=datetime.now(UTC),
            details={
                "tool": self.name,
                "audit_run_id": run_id,
                "audited_at": snapshot.audited_at.isoformat(),
                "pass_count": pass_count,
                "fail_count": len(fail_accounts),
                "unknown_count": len(unknown_accounts),
                "exempt_count": exempt_count,
                "non_compliant_accounts": fail_accounts,
                "unknown_accounts": unknown_accounts,
                "exempt_accounts": sorted(exempt_accounts),
                "inspector_notes": snapshot.inspector_notes,
            },
        )
        await self._record(result)

        if fail_accounts:
            await self.ctx.event_bus.publish(
                "alert.security.twofa_audit",
                {
                    "event_type": "security_twofa_audit",
                    "generated_at": snapshot.audited_at.isoformat(),
                    "non_compliant_accounts": fail_accounts,
                    "unknown_accounts": unknown_accounts,
                    "exempt_accounts": sorted(exempt_accounts),
                },
            )
        return result

    async def _persist_snapshot(
        self,
        snapshot: TwoFactorAuditSnapshot,
        *,
        exempt_accounts: set[str],
    ) -> int:
        assert self.ctx.db is not None
        connection = self.ctx.db.connection
        non_exempt_accounts = [account for account in snapshot.accounts if not account.is_exempt]
        pass_count = sum(1 for account in non_exempt_accounts if account.status == "pass")
        fail_count = sum(1 for account in non_exempt_accounts if account.status == "fail")
        unknown_count = sum(1 for account in non_exempt_accounts if account.status == "unknown")
        exempt_count = sum(1 for account in snapshot.accounts if account.is_exempt)
        cursor = await connection.execute(
            """
            INSERT INTO twofa_audit_runs (
                audited_at,
                pass_count,
                fail_count,
                unknown_count,
                exempt_count,
                non_compliant_count,
                exempt_accounts_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot.audited_at.isoformat(),
                pass_count,
                fail_count,
                unknown_count,
                exempt_count,
                fail_count,
                json.dumps(sorted(exempt_accounts)),
            ),
        )
        run_id_raw = cursor.lastrowid
        if run_id_raw is None:
            raise RuntimeError("Failed to obtain 2FA audit run row id after insert")
        run_id = int(run_id_raw)

        await connection.executemany(
            """
            INSERT INTO twofa_audit_accounts (
                audit_run_id,
                username,
                status,
                reason,
                methods_json,
                is_exempt
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    account.username,
                    account.status,
                    account.reason,
                    json.dumps(account.methods),
                    1 if account.is_exempt else 0,
                )
                for account in snapshot.accounts
            ],
        )
        await connection.commit()
        return run_id

    async def _record(self, result: ToolResult) -> None:
        await self.ctx.audit.append(
            action_type="tool_run",
            source="scheduler",
            description=result.summary,
            outcome=result.outcome.value,
            details=result.details,
        )

    def _exempt_accounts(self) -> set[str]:
        raw = self.config.get("exempt_accounts", [])
        if not isinstance(raw, list):
            return set()
        return {str(item).strip() for item in raw if str(item).strip()}
