from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import re
import shutil
from typing import TYPE_CHECKING, Any, Protocol

from system_sentinel.core.time_config import parse_duration_hhmmss
from system_sentinel.db.vulnerability_repository import VulnerabilityRepository
from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext

_DEFAULT_SCHEDULE = "7d 00:00:00"
_DEFAULT_REPORT_PATH = Path("/var/log/lynis-report.dat")
_DEFAULT_SCORE_DROP_ALERT_THRESHOLD = 10
_DEFAULT_LYNIS_ARGS = ["audit", "system", "--quick", "--no-colors"]
_FIRST_INT_RE = re.compile(r"(\d+)")
_INDEX_RE = re.compile(r"hardening\s*index\s*:\s*(?:\[\s*)?(?P<score>\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ParsedLynisReport:
    score: int | None
    warnings: list[str]
    suggestions: list[str]

    @property
    def warning_count(self) -> int:
        return len(self.warnings)

    @property
    def suggestion_count(self) -> int:
        return len(self.suggestions)

    @property
    def top_findings(self) -> list[str]:
        findings = [*self.warnings, *self.suggestions]
        return findings[:5]


class VulnerabilityCommandRunner(Protocol):
    async def run(self, args: list[str]) -> CommandResult: ...


class LocalVulnerabilityCommandRunner:
    async def run(self, args: list[str]) -> CommandResult:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return CommandResult(
            returncode=int(process.returncode or 0),
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
        )


class VulnScanTool(BaseTool):
    name = "vulnscan"
    display_name = "Vulnerability Scan"
    description = "Runs Lynis scans and reports security posture trends."

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        *,
        runner: VulnerabilityCommandRunner | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self.config.setdefault("run_on_startup", False)
        self._runner = runner or LocalVulnerabilityCommandRunner()
        self._lynis_path = shutil.which("lynis")
        if self.is_enabled() and self._lynis_path is None:
            self.ctx.logger.getChild("tool.vulnscan").warning(
                "Lynis is not installed; vulnerability scanning will be skipped."
            )

    def schedule(self) -> str | None:
        raw = self.config.get("schedule")
        if raw is None:
            return _DEFAULT_SCHEDULE
        parsed = parse_duration_hhmmss(raw)
        if parsed is None or parsed[0] <= 0:
            self.ctx.logger.getChild("tool.vulnscan").warning(
                "Invalid vulnscan schedule %r; expected HH:MM:SS or <days>d HH:MM:SS. "
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
                summary="Vulnerability scan tool is disabled.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        lynis_path = self._lynis_path or shutil.which("lynis")
        if lynis_path is None:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.SKIPPED,
                summary="Lynis is not installed; skipping vulnerability scan.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                details={"tool": self.name, "skipped_reason": "lynis_not_installed"},
            )
            await self._record(result)
            return result
        self._lynis_path = lynis_path

        scan_time = datetime.now(UTC)
        report_path = self._report_path()
        command = [lynis_path, *self._lynis_args()]
        command_result = await self._runner.run(command)
        if command_result.returncode != 0:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Lynis vulnerability scan failed.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=command_result.stderr.strip() or "lynis exited non-zero",
                details={
                    "tool": self.name,
                    "command": command,
                    "returncode": command_result.returncode,
                    "stdout": command_result.stdout[:4096],
                    "stderr": command_result.stderr[:4096],
                },
            )
            await self._record(result)
            return result

        report_text = await self._read_report(report_path)
        parsed = self._parse_lynis_report(report_text=report_text, stdout=command_result.stdout)
        db = self.ctx.db
        if db is None:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Vulnerability scan persistence unavailable: database not configured.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                details={"tool": self.name},
            )
            await self._record(result)
            return result
        repo = VulnerabilityRepository(db)
        previous_scan = await repo.latest_scan_before(scan_time)
        persisted = await repo.record_scan(
            scanned_at=scan_time,
            score=parsed.score,
            warning_count=parsed.warning_count,
            suggestion_count=parsed.suggestion_count,
            top_findings=parsed.top_findings,
            report_text=report_text,
            report_path=str(report_path),
        )
        summary = (
            "Vulnerability scan completed. "
            f"score={self._format_score(parsed.score)}, "
            f"warnings={parsed.warning_count}, "
            f"suggestions={parsed.suggestion_count}."
        )
        result = ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary=summary,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            details={
                "tool": self.name,
                "scan_id": persisted["scan_id"],
                "scanned_at": persisted["scanned_at"],
                "score": parsed.score,
                "warning_count": parsed.warning_count,
                "suggestion_count": parsed.suggestion_count,
                "vulnerability_count": parsed.warning_count,
                "top_findings": parsed.top_findings,
                "report_path": str(report_path),
            },
        )
        await self._record(result)
        await self.ctx.event_bus.publish(
            "alert.vulnscan.summary",
            {
                "event_type": "vulnscan_summary",
                "generated_at": scan_time.isoformat(),
                "score": parsed.score,
                "warning_count": parsed.warning_count,
                "suggestion_count": parsed.suggestion_count,
                "top_findings": parsed.top_findings,
            },
        )

        previous_score = self._extract_score(previous_scan)
        threshold = self._score_drop_alert_threshold()
        if (
            parsed.score is not None
            and previous_score is not None
            and (previous_score - parsed.score) > threshold
        ):
            await self.ctx.event_bus.publish(
                "alert.vulnscan.score_drop",
                {
                    "event_type": "vulnscan_score_drop",
                    "generated_at": scan_time.isoformat(),
                    "previous_score": previous_score,
                    "current_score": parsed.score,
                    "drop_amount": previous_score - parsed.score,
                    "threshold": threshold,
                },
            )
        return result

    async def _record(self, result: ToolResult) -> None:
        await self.ctx.audit.append(
            action_type="tool_run",
            source="scheduler",
            description=result.summary,
            outcome=result.outcome.value,
            details=result.details,
        )

    async def _read_report(self, report_path: Path) -> str:
        try:
            return await asyncio.to_thread(report_path.read_text)
        except FileNotFoundError:
            return ""
        except OSError as exc:
            self.ctx.logger.getChild("tool.vulnscan").warning(
                "Failed to read Lynis report file %s: %s",
                report_path,
                exc,
            )
            return ""

    def _score_drop_alert_threshold(self) -> int:
        raw = self.config.get("score_drop_alert_threshold", _DEFAULT_SCORE_DROP_ALERT_THRESHOLD)
        if isinstance(raw, int) and raw >= 0:
            return raw
        if isinstance(raw, float) and raw >= 0:
            return int(raw)
        if isinstance(raw, str):
            stripped = raw.strip()
            if stripped.isdigit():
                return int(stripped)
        return _DEFAULT_SCORE_DROP_ALERT_THRESHOLD

    def _report_path(self) -> Path:
        raw = self.config.get("report_path")
        if isinstance(raw, str) and raw.strip():
            return Path(raw.strip())
        return _DEFAULT_REPORT_PATH

    def _lynis_args(self) -> list[str]:
        raw = self.config.get("lynis_args")
        if not isinstance(raw, list):
            return list(_DEFAULT_LYNIS_ARGS)
        args = [str(item).strip() for item in raw if str(item).strip()]
        return args if args else list(_DEFAULT_LYNIS_ARGS)

    def _parse_lynis_report(self, *, report_text: str, stdout: str) -> ParsedLynisReport:
        score: int | None = None
        warnings: list[str] = []
        suggestions: list[str] = []
        for raw_line in report_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            normalized = key.strip().lower()
            parsed_value = self._normalize_finding(value)
            if normalized == "hardening_index":
                score = self._extract_first_int(parsed_value)
                continue
            if normalized.startswith("warning["):
                if parsed_value:
                    warnings.append(parsed_value)
                continue
            if normalized.startswith("suggestion["):
                if parsed_value:
                    suggestions.append(parsed_value)
                continue

        if score is None:
            score_match = _INDEX_RE.search(stdout)
            if score_match is not None:
                score = int(score_match.group("score"))

        return ParsedLynisReport(score=score, warnings=warnings, suggestions=suggestions)

    def _normalize_finding(self, raw: str) -> str:
        stripped = raw.strip()
        if not stripped:
            return ""
        pieces = [piece.strip() for piece in stripped.split("|") if piece.strip()]
        if pieces:
            stripped = pieces[-1]
        return " ".join(stripped.split())

    def _extract_first_int(self, raw: str) -> int | None:
        match = _FIRST_INT_RE.search(raw)
        if match is None:
            return None
        return int(match.group(1))

    def _extract_score(self, scan: dict[str, Any] | None) -> int | None:
        if scan is None:
            return None
        raw = scan.get("score")
        if isinstance(raw, int):
            return raw
        if isinstance(raw, float):
            return int(raw)
        if isinstance(raw, str):
            match = _FIRST_INT_RE.search(raw)
            if match is not None:
                return int(match.group(1))
        return None

    def _format_score(self, score: int | None) -> str:
        return str(score) if score is not None else "n/a"
