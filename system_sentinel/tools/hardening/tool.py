from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import re
import subprocess
from typing import TYPE_CHECKING, Any, Protocol

from system_sentinel.core.time_config import parse_duration_hhmmss
from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext

_DEFAULT_SCHEDULE = "7d 00:00:00"
_SSH_MAIN_CONFIG = Path("/etc/ssh/sshd_config")
_SSH_CONFIG_DIR = Path("/etc/ssh/sshd_config.d")
_SSH_MANAGED_CONFIG = _SSH_CONFIG_DIR / "99-system-sentinel-hardening.conf"
_SYSCTL_MANAGED_CONFIG = Path("/etc/sysctl.d/99-system-sentinel-hardening.conf")
_PWQUALITY_MAIN_CONFIG = Path("/etc/security/pwquality.conf")
_PWQUALITY_CONFIG_DIR = Path("/etc/security/pwquality.conf.d")
_PWQUALITY_MANAGED_CONFIG = _PWQUALITY_CONFIG_DIR / "99-system-sentinel-hardening.conf"

_DEFAULT_SYSCTL: dict[str, str] = {
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.tcp_syncookies": "1",
    "kernel.randomize_va_space": "2",
}
_DEFAULT_UNNECESSARY_SERVICES = [
    "telnet.socket",
    "rsh.socket",
    "rlogin.socket",
    "rexec.socket",
]


@dataclass(frozen=True)
class HardeningCheckResult:
    check_id: str
    title: str
    passed: bool
    details: str
    remediated: bool = False
    remediation: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class HardeningBackend(Protocol):
    def read_text(self, path: Path) -> str | None: ...

    def write_text(self, path: Path, content: str) -> None: ...

    def list_matching(self, pattern: str) -> list[Path]: ...

    def run(self, args: list[str]) -> CommandResult: ...


class LocalHardeningBackend:
    def read_text(self, path: Path) -> str | None:
        try:
            return path.read_text()
        except FileNotFoundError:
            return None

    def write_text(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def list_matching(self, pattern: str) -> list[Path]:
        if pattern.startswith("/"):
            return sorted(Path("/").glob(pattern[1:]))
        return sorted(Path().glob(pattern))

    def run(self, args: list[str]) -> CommandResult:
        proc = subprocess.run(args, capture_output=True, text=True, check=False)
        return CommandResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )


class HardeningTool(BaseTool):
    name = "hardening"
    display_name = "System Hardening"
    description = "Audits and remediates CIS-style hardening checks."

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        backend: HardeningBackend | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self.config.setdefault("run_on_startup", True)
        self._backend = backend or LocalHardeningBackend()

    def schedule(self) -> str | None:
        raw = self.config.get("schedule")
        if raw is None:
            return _DEFAULT_SCHEDULE
        parsed = parse_duration_hhmmss(raw)
        if parsed is None or parsed[0] <= 0:
            self.ctx.logger.getChild("tool.hardening").warning(
                "Invalid hardening schedule %r; expected HH:MM:SS or <days>d HH:MM:SS. "
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
                summary="Hardening tool is disabled.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        checks = self._enabled_checks()
        if not checks:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.SKIPPED,
                summary="No hardening checks enabled.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                details={
                    "tool": self.name,
                    "checks": [],
                    "auto_remediate": bool(self.config.get("auto_remediate", False)),
                },
            )
            await self._record(result)
            return result

        auto_remediate = bool(self.config.get("auto_remediate", False))
        outcomes: list[HardeningCheckResult] = []
        for check_id in checks:
            outcomes.append(self._run_check(check_id, auto_remediate=auto_remediate))

        failing = [item for item in outcomes if not item.passed]
        remediated = [item for item in outcomes if item.remediated]
        post_remediation_failures = [item for item in failing if not item.remediated]
        if post_remediation_failures:
            summary = (
                f"Hardening audit found {len(post_remediation_failures)} failing check(s); "
                f"remediated {len(remediated)}."
            )
            outcome = ToolOutcome.FAILURE
        else:
            summary = (
                f"Hardening audit passed ({len(outcomes)}/{len(outcomes)}); "
                f"remediated {len(remediated)}."
            )
            outcome = ToolOutcome.SUCCESS

        details = {
            "tool": self.name,
            "auto_remediate": auto_remediate,
            "benchmarks": self._benchmarks_config(),
            "checks": [
                {
                    "id": check.check_id,
                    "title": check.title,
                    "status": "pass" if check.passed else "fail",
                    "details": check.details,
                    "remediated": check.remediated,
                    "remediation": check.remediation,
                    "error": check.error,
                }
                for check in outcomes
            ],
            "failed_checks": [check.check_id for check in post_remediation_failures],
            "remediated_checks": [check.check_id for check in remediated],
        }
        result = ToolResult(
            tool_name=self.name,
            outcome=outcome,
            summary=summary,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            details=details,
        )
        await self._record(result)
        for check in remediated:
            await self.ctx.event_bus.publish(
                "alert.hardening.auto_remediated",
                {
                    "check_id": check.check_id,
                    "title": check.title,
                    "details": check.details,
                    "remediation": check.remediation or "Applied configured hardening fix.",
                },
            )
        return result

    def _enabled_checks(self) -> list[str]:
        all_checks = [
            "ssh_disable_root_login",
            "ssh_disable_password_auth",
            "sysctl_hardening",
            "disable_unnecessary_services",
            "strong_password_policy",
        ]
        enabled: dict[str, bool] = {}
        benchmarks = self._benchmarks_config()
        if bool(benchmarks.get("cis_level_1", True)):
            enabled = {check: True for check in all_checks}

        raw_overrides = self.config.get("checks", {})
        overrides = raw_overrides if isinstance(raw_overrides, dict) else {}
        for check in all_checks:
            if check in overrides:
                enabled[check] = bool(overrides.get(check))
            elif check not in enabled:
                enabled[check] = False
        return [check for check, is_enabled in enabled.items() if is_enabled]

    def _benchmarks_config(self) -> dict[str, Any]:
        raw = self.config.get("benchmarks", {})
        if isinstance(raw, dict):
            return raw
        return {}

    def _run_check(self, check_id: str, *, auto_remediate: bool) -> HardeningCheckResult:
        if check_id == "ssh_disable_root_login":
            return self._check_ssh_setting(
                check_id=check_id,
                title="SSH root login disabled",
                key="PermitRootLogin",
                expected="no",
                auto_remediate=auto_remediate,
            )
        if check_id == "ssh_disable_password_auth":
            return self._check_ssh_setting(
                check_id=check_id,
                title="SSH password authentication disabled",
                key="PasswordAuthentication",
                expected="no",
                auto_remediate=auto_remediate,
            )
        if check_id == "sysctl_hardening":
            return self._check_sysctl_hardening(auto_remediate=auto_remediate)
        if check_id == "disable_unnecessary_services":
            return self._check_services(auto_remediate=auto_remediate)
        if check_id == "strong_password_policy":
            return self._check_password_policy(auto_remediate=auto_remediate)
        return HardeningCheckResult(
            check_id=check_id,
            title=check_id,
            passed=False,
            details="Unknown hardening check identifier.",
            error="unknown_check",
        )

    def _check_ssh_setting(
        self,
        *,
        check_id: str,
        title: str,
        key: str,
        expected: str,
        auto_remediate: bool,
    ) -> HardeningCheckResult:
        current = self._effective_ssh_setting(key)
        if current == expected:
            return HardeningCheckResult(
                check_id=check_id,
                title=title,
                passed=True,
                details=f"{key}={expected}",
            )
        details = f"{key} expected '{expected}' but found '{current or 'unset'}'."
        if not auto_remediate:
            return HardeningCheckResult(
                check_id=check_id,
                title=title,
                passed=False,
                details=details,
            )
        try:
            self._ensure_ssh_setting(key=key, value=expected)
            self._reload_ssh()
        except OSError as exc:
            return HardeningCheckResult(
                check_id=check_id,
                title=title,
                passed=False,
                details=details,
                error=str(exc),
            )
        return HardeningCheckResult(
            check_id=check_id,
            title=title,
            passed=True,
            details=details,
            remediated=True,
            remediation=f"Updated {_SSH_MANAGED_CONFIG} and reloaded SSH service.",
        )

    def _check_sysctl_hardening(self, *, auto_remediate: bool) -> HardeningCheckResult:
        desired = self._desired_sysctl()
        mismatches: list[str] = []
        for key, expected in desired.items():
            proc = self._backend.run(["sysctl", "-n", key])
            if proc.returncode != 0:
                mismatches.append(f"{key}=error")
                continue
            actual = proc.stdout.strip()
            if actual != expected:
                mismatches.append(f"{key}={actual}")
        if not mismatches:
            return HardeningCheckResult(
                check_id="sysctl_hardening",
                title="Kernel sysctl hardening",
                passed=True,
                details=f"{len(desired)} parameter(s) match desired values.",
            )
        details = f"Mismatched sysctl values: {', '.join(mismatches)}"
        if not auto_remediate:
            return HardeningCheckResult(
                check_id="sysctl_hardening",
                title="Kernel sysctl hardening",
                passed=False,
                details=details,
            )
        try:
            body = "\n".join([f"{key} = {value}" for key, value in desired.items()]) + "\n"
            self._backend.write_text(_SYSCTL_MANAGED_CONFIG, body)
            apply_result = self._backend.run(["sysctl", "--system"])
            if apply_result.returncode != 0:
                return HardeningCheckResult(
                    check_id="sysctl_hardening",
                    title="Kernel sysctl hardening",
                    passed=False,
                    details=details,
                    error=apply_result.stderr.strip() or "sysctl --system failed",
                )
        except OSError as exc:
            return HardeningCheckResult(
                check_id="sysctl_hardening",
                title="Kernel sysctl hardening",
                passed=False,
                details=details,
                error=str(exc),
            )
        return HardeningCheckResult(
            check_id="sysctl_hardening",
            title="Kernel sysctl hardening",
            passed=True,
            details=details,
            remediated=True,
            remediation=f"Wrote {_SYSCTL_MANAGED_CONFIG} and applied sysctl settings.",
        )

    def _check_services(self, *, auto_remediate: bool) -> HardeningCheckResult:
        raw = self.config.get("unnecessary_services", _DEFAULT_UNNECESSARY_SERVICES)
        services = (
            [str(item).strip() for item in raw if isinstance(item, str)]
            if isinstance(raw, list)
            else []
        )
        enabled: list[str] = []
        for service in services:
            proc = self._backend.run(["systemctl", "is-enabled", service])
            if proc.returncode == 0 and proc.stdout.strip() in {
                "enabled",
                "enabled-runtime",
                "linked",
            }:
                enabled.append(service)
        if not enabled:
            return HardeningCheckResult(
                check_id="disable_unnecessary_services",
                title="Unnecessary services disabled",
                passed=True,
                details="All configured unnecessary services are disabled.",
            )
        details = f"Enabled unnecessary services: {', '.join(enabled)}"
        if not auto_remediate:
            return HardeningCheckResult(
                check_id="disable_unnecessary_services",
                title="Unnecessary services disabled",
                passed=False,
                details=details,
            )

        failed: list[str] = []
        for service in enabled:
            proc = self._backend.run(["systemctl", "disable", "--now", service])
            if proc.returncode != 0:
                failed.append(service)
        if failed:
            return HardeningCheckResult(
                check_id="disable_unnecessary_services",
                title="Unnecessary services disabled",
                passed=False,
                details=details,
                error=f"Failed to disable: {', '.join(failed)}",
            )
        return HardeningCheckResult(
            check_id="disable_unnecessary_services",
            title="Unnecessary services disabled",
            passed=True,
            details=details,
            remediated=True,
            remediation=f"Disabled and stopped: {', '.join(enabled)}.",
        )

    def _check_password_policy(self, *, auto_remediate: bool) -> HardeningCheckResult:
        desired = self._desired_password_policy()
        parsed = self._effective_pwquality_settings()
        minlen_value = _safe_int(parsed.get("minlen"))
        minclass_value = _safe_int(parsed.get("minclass"))
        minlen_ok = minlen_value is not None and minlen_value >= desired["minlen"]
        minclass_ok = minclass_value is not None and minclass_value >= desired["minclass"]
        if minlen_ok and minclass_ok:
            return HardeningCheckResult(
                check_id="strong_password_policy",
                title="Strong password policy enforced",
                passed=True,
                details=(
                    f"minlen={minlen_value} (required>={desired['minlen']}), "
                    f"minclass={minclass_value} (required>={desired['minclass']})"
                ),
            )

        details = (
            f"Password policy weak: minlen={minlen_value}, minclass={minclass_value}. "
            f"Required minlen>={desired['minlen']}, minclass>={desired['minclass']}."
        )
        if not auto_remediate:
            return HardeningCheckResult(
                check_id="strong_password_policy",
                title="Strong password policy enforced",
                passed=False,
                details=details,
            )
        try:
            body = (
                "# Managed by SystemSentinel hardening\n"
                f"minlen = {desired['minlen']}\n"
                f"minclass = {desired['minclass']}\n"
            )
            self._backend.write_text(_PWQUALITY_MANAGED_CONFIG, body)
        except OSError as exc:
            return HardeningCheckResult(
                check_id="strong_password_policy",
                title="Strong password policy enforced",
                passed=False,
                details=details,
                error=str(exc),
            )
        return HardeningCheckResult(
            check_id="strong_password_policy",
            title="Strong password policy enforced",
            passed=True,
            details=details,
            remediated=True,
            remediation=f"Wrote {_PWQUALITY_MANAGED_CONFIG}.",
        )

    def _effective_ssh_setting(self, key: str) -> str | None:
        values: list[str] = []
        sources = [_SSH_MAIN_CONFIG, *self._backend.list_matching("/etc/ssh/sshd_config.d/*.conf")]
        for path in sources:
            text = self._backend.read_text(path)
            if text is None:
                continue
            value = _parse_last_key_value(text, key)
            if value is not None:
                values.append(value.lower())
        return values[-1] if values else None

    def _ensure_ssh_setting(self, *, key: str, value: str) -> None:
        existing = self._backend.read_text(_SSH_MANAGED_CONFIG) or ""
        updated = _replace_or_append_key(existing, key, value)
        self._backend.write_text(_SSH_MANAGED_CONFIG, updated)

    def _reload_ssh(self) -> None:
        result = self._backend.run(["systemctl", "reload", "sshd"])
        if result.returncode == 0:
            return
        fallback = self._backend.run(["systemctl", "reload", "ssh"])
        if fallback.returncode != 0:
            msg = fallback.stderr.strip() or result.stderr.strip() or "failed to reload ssh service"
            raise OSError(msg)

    def _desired_sysctl(self) -> dict[str, str]:
        raw = self.config.get("sysctl", _DEFAULT_SYSCTL)
        if not isinstance(raw, dict):
            return dict(_DEFAULT_SYSCTL)
        parsed: dict[str, str] = {}
        for key, value in raw.items():
            if not isinstance(key, str):
                continue
            parsed[key] = str(value)
        return parsed or dict(_DEFAULT_SYSCTL)

    def _desired_password_policy(self) -> dict[str, int]:
        raw = self.config.get("password_policy", {})
        policy = raw if isinstance(raw, dict) else {}
        minlen_raw = policy.get("minlen", 14)
        minclass_raw = policy.get("minclass", 3)
        minlen = _safe_int(minlen_raw) or 14
        minclass = _safe_int(minclass_raw) or 3
        return {"minlen": minlen, "minclass": minclass}

    def _effective_pwquality_settings(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for path in [
            _PWQUALITY_MAIN_CONFIG,
            *self._backend.list_matching("/etc/security/pwquality.conf.d/*.conf"),
        ]:
            text = self._backend.read_text(path)
            if text is None:
                continue
            merged.update(_parse_key_value_map(text))
        return merged

    async def _record(self, result: ToolResult) -> None:
        await self.ctx.audit.append(
            action_type="tool_run",
            source="scheduler",
            description=result.summary,
            outcome=result.outcome.value,
            details=result.details,
        )


def _safe_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _parse_last_key_value(text: str, key: str) -> str | None:
    pattern = re.compile(rf"^{re.escape(key)}\s+(.+)$", re.IGNORECASE)
    value: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        matched = pattern.match(line)
        if matched:
            value = matched.group(1).strip()
    return value


def _replace_or_append_key(text: str, key: str, value: str) -> str:
    lines = text.splitlines()
    pattern = re.compile(rf"^\s*{re.escape(key)}\s+")
    replaced = False
    output: list[str] = []
    for line in lines:
        if pattern.match(line):
            output.append(f"{key} {value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{key} {value}")
    return "\n".join(output).rstrip() + "\n"


def _parse_key_value_map(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed_key = key.strip().lower()
        parsed_value = value.strip()
        if parsed_key:
            result[parsed_key] = parsed_value
    return result
