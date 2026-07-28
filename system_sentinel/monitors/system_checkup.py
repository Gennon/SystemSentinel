"""Scheduled AI full system check monitor (US-045).

Runs on a configurable schedule, gathers data from all sentinel sources,
calls the LLM to synthesize a prioritized health report, and publishes
an ``alert.system.checkup`` event for the alert handler to forward to chat.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.command_checkup import (
    _CHECKUP_SYSTEM_PROMPT,
    _make_repos,
    build_checkup_prompt,
    gather_checkup_context,
)
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.connection import DatabaseConnection

_LAST_SENT_KEY = "system_checkup.last_sent_at_utc"


class SystemCheckupMonitor(BaseMonitor):
    """Scheduled AI-powered full system health check (US-045)."""

    name = "system_checkup"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        db: DatabaseConnection | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._db = db

    async def collect(self) -> None:
        llm_client = self.ctx.llm
        if llm_client is None or not llm_client.is_enabled:
            self.logger.debug("LLM not configured — skipping scheduled system checkup.")
            return

        db = self._db
        if db is None:
            self.logger.warning("No database connection — skipping scheduled system checkup.")
            return

        try:
            vuln_repo, login_repo, integrity_repo, audit_repo = _make_repos(db)
            context = await gather_checkup_context(
                vuln_repo=vuln_repo,
                login_repo=login_repo,
                integrity_repo=integrity_repo,
                audit_repo=audit_repo,
            )
            prompt = build_checkup_prompt(context)

            result = await llm_client.complete(
                prompt=prompt,
                system_prompt=_CHECKUP_SYSTEM_PROMPT,
                timeout_seconds=self._timeout_seconds(),
            )
            report = str(result.text).strip()
        except Exception as exc:
            self.logger.error("Scheduled system checkup failed: %s", exc, exc_info=exc)
            return

        generated_at = datetime.now(UTC).isoformat()

        await self.ctx.audit.append(
            action_type="system_checkup",
            source="scheduler:system_checkup",
            description="Scheduled AI full system check completed.",
            outcome="success",
            details={
                "provider": result.provider,
                "model": result.model_used,
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "resource_snapshot": context.get("resources", {}),
                "anomaly_count": len(context.get("login_anomalies", [])),
                "alert_count": len(context.get("recent_alerts", [])),
                "integrity_mismatches": len(context.get("integrity_mismatches", [])),
            },
        )

        await self.ctx.event_bus.publish(
            "alert.system.checkup",
            {
                "generated_at": generated_at,
                "report": report,
                "provider": result.provider,
                "model": result.model_used,
                "resource_snapshot": context.get("resources", {}),
            },
        )

    def _timeout_seconds(self) -> float:
        raw = self.config.get("timeout_seconds", 60.0)
        try:
            val = float(str(raw))
        except (TypeError, ValueError):
            return 60.0
        return val if val > 0 else 60.0
