"""Alert correlation service.

Buffers incoming alerts within a configurable time window, then uses the LLM
to determine whether they share a common root cause.  When correlated, a single
summary message is sent to chat instead of one message per alert.

Config path: ``llm.alert_correlation``

Example::

    llm:
      alert_correlation:
        enabled: true
        window_seconds: 300   # 5 minutes (default)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from system_sentinel.chat.base import AlertSeverity, OutboundMessage

_SEVERITY_RANK: dict[AlertSeverity, int] = {
    AlertSeverity.INFO: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.CRITICAL: 2,
}

_DEFAULT_WINDOW_SECONDS = 300.0


@dataclass
class _PendingAlert:
    event_type: str
    payload: Any
    message: OutboundMessage
    received_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class AlertCorrelationService:
    """Groups simultaneous alerts and optionally replaces them with a single root-cause report."""

    def __init__(
        self,
        *,
        router: Any,
        audit: Any,
        llm: Any,
        logger: Any,
        enabled: bool,
        window_seconds: float = _DEFAULT_WINDOW_SECONDS,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._router = router
        self._audit = audit
        self._llm = llm
        self._logger = logger
        self._enabled = enabled
        self._window_seconds = window_seconds
        self._timeout_seconds = timeout_seconds
        self._pending: list[_PendingAlert] = []
        self._flush_task: asyncio.Task[None] | None = None
        self._background_tasks: set[asyncio.Task[None]] = set()

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def submit(self, event_type: str, payload: Any, msg: OutboundMessage) -> None:
        """Buffer *msg* for correlation.  The caller must NOT broadcast it directly."""
        self._pending.append(_PendingAlert(event_type=event_type, payload=payload, message=msg))
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._window_flush())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _window_flush(self) -> None:
        await asyncio.sleep(self._window_seconds)
        task = asyncio.create_task(self._flush())
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _flush(self) -> None:
        if not self._pending:
            return
        batch = list(self._pending)
        self._pending.clear()

        if len(batch) == 1:
            await self._router.broadcast(batch[0].message)
            await self._record_decision(batch, correlated=False, reason="single_alert")
            return

        # Multiple alerts: try LLM correlation.
        if self._llm is None or not self._llm.is_enabled:
            for alert in batch:
                await self._router.broadcast(alert.message)
            await self._record_decision(batch, correlated=False, reason="llm_unavailable")
            return

        correlated_msg: OutboundMessage | None = None
        failure_reason: str | None = None
        try:
            result = await asyncio.wait_for(
                self._llm.complete(
                    prompt=self._build_prompt(batch),
                    system_prompt=self._system_prompt(),
                    timeout_seconds=self._timeout_seconds,
                ),
                self._timeout_seconds,
            )
            correlated_msg = self._parse_llm_response(result.text, batch)
        except TimeoutError:
            failure_reason = "llm_timeout"
        except Exception as exc:
            self._logger.warning("Alert correlation LLM call failed: %s", exc)
            failure_reason = f"llm_error: {exc}"

        if failure_reason is not None:
            for alert in batch:
                await self._router.broadcast(alert.message)
            await self._record_decision(batch, correlated=False, reason=failure_reason)
            return

        if correlated_msg is not None:
            await self._router.broadcast(correlated_msg)
            await self._record_decision(batch, correlated=True, reason="llm_correlation")
        else:
            for alert in batch:
                await self._router.broadcast(alert.message)
            await self._record_decision(batch, correlated=False, reason="no_common_root_cause")

    # ------------------------------------------------------------------
    # LLM prompt helpers
    # ------------------------------------------------------------------

    def _system_prompt(self) -> str:
        return (
            "You are SystemSentinel's alert correlation engine. "
            "Analyse the list of simultaneous alerts and determine if they share a common root cause. "
            "If they do, respond with exactly:\n"
            "CORRELATED: <root cause in one sentence>\n"
            "<optional brief explanation>\n\n"
            "If they do NOT share a root cause, respond with exactly: NOT_CORRELATED"
        )

    def _build_prompt(self, batch: list[_PendingAlert]) -> str:
        lines = [
            f"The following {len(batch)} alerts fired within a short time window.",
            "Do they share a common root cause?",
            "",
        ]
        for i, alert in enumerate(batch, 1):
            lines.append(f"Alert {i}: [{alert.event_type}] {alert.message.title or '(no title)'}")
            if alert.message.text:
                summary = alert.message.text.strip().splitlines()[0][:300]
                lines.append(f"  Details: {summary}")
            lines.append("")
        return "\n".join(lines)

    def _parse_llm_response(self, text: str, batch: list[_PendingAlert]) -> OutboundMessage | None:
        """Return a correlated OutboundMessage or None if the LLM found no correlation."""
        stripped = text.strip()
        if not stripped.upper().startswith("CORRELATED:"):
            return None

        first_line = stripped.splitlines()[0]
        root_cause = first_line[len("CORRELATED:") :].strip()
        explanation = "\n".join(stripped.splitlines()[1:]).strip()

        contributing = "\n".join(
            f"• [{a.event_type}] {a.message.title or a.event_type}" for a in batch
        )

        parts = [
            f"**Root cause:** {root_cause}",
            "",
            "**Contributing alerts:**",
            contributing,
        ]
        if explanation:
            parts.extend(["", explanation])

        highest_severity = max(
            (a.message.severity for a in batch),
            key=lambda s: _SEVERITY_RANK[s],
        )

        return OutboundMessage(
            title=f"🔗 Correlated alert: {root_cause[:80]}",
            text="\n".join(parts),
            severity=highest_severity,
        )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    async def _record_decision(
        self,
        batch: list[_PendingAlert],
        *,
        correlated: bool,
        reason: str,
    ) -> None:
        if self._audit is None:
            return
        event_types = [a.event_type for a in batch]
        outcome = "correlated" if correlated else "not_correlated"
        description = (
            f"Alert correlation: grouped {len(batch)} alert(s) into single root-cause report."
            if correlated
            else f"Alert correlation: {len(batch)} alert(s) sent individually ({reason})."
        )
        await self._audit.append(
            action_type="alert_correlation",
            source="alert.correlation",
            description=description,
            outcome=outcome,
            details={
                "alert_count": len(batch),
                "event_types": event_types,
                "reason": reason,
                "correlated": correlated,
            },
        )
