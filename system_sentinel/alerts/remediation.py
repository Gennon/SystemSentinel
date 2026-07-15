from __future__ import annotations

import asyncio
from time import monotonic
from typing import Any

import psutil

from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.core.exceptions import LLMUnavailableError


class AlertLLMRemediationService:
    def __init__(
        self,
        *,
        router: Any,
        audit: Any,
        llm: Any,
        logger: Any,
        enabled: bool,
        timeout_seconds: float,
    ) -> None:
        self._router = router
        self._audit = audit
        self._llm = llm
        self._logger = logger
        self._enabled = enabled
        self._timeout_seconds = timeout_seconds
        self._background_tasks: set[asyncio.Task[None]] = set()

    async def maybe_send(
        self,
        *,
        event_type: str,
        payload: Any,
        alert: OutboundMessage,
        wait_for_fn: Any,
    ) -> None:
        llm_client = self._llm
        if not self._enabled:
            return
        if llm_client is None or not llm_client.is_enabled:
            return

        system_prompt = (
            "You are SystemSentinel's remediation assistant. "
            "Provide concise, low-risk, actionable remediation steps. "
            "Do not suggest automatic execution and avoid destructive actions unless explicitly justified."
        )
        prompt = self._build_prompt(event_type=event_type, payload=payload, alert=alert)
        started = monotonic()
        request_task = asyncio.create_task(
            llm_client.complete(
                prompt=prompt,
                system_prompt=system_prompt,
                timeout_seconds=self._timeout_seconds,
            )
        )
        try:
            result = await wait_for_fn(asyncio.shield(request_task), 15.0)
        except TimeoutError:
            follow_up = asyncio.create_task(
                self._publish_delayed(
                    request_task=request_task,
                    event_type=event_type,
                    alert=alert,
                    started=started,
                )
            )
            self._track_background_task(follow_up)
            return
        except LLMUnavailableError as exc:
            await self._record_failure(event_type=event_type, reason=str(exc))
            return
        except Exception as exc:
            self._logger.warning(
                "LLM remediation generation failed for %s: %s",
                event_type,
                exc,
            )
            await self._record_failure(event_type=event_type, reason=str(exc))
            return

        await self._publish_message(
            event_type=event_type,
            alert=alert,
            suggestion=result.text,
            provider=result.provider,
            model=result.model_used,
            elapsed_seconds=monotonic() - started,
            delayed=False,
        )

    async def _publish_delayed(
        self,
        *,
        request_task: asyncio.Task[Any],
        event_type: str,
        alert: OutboundMessage,
        started: float,
    ) -> None:
        try:
            result = await request_task
        except LLMUnavailableError as exc:
            await self._record_failure(event_type=event_type, reason=str(exc))
            return
        except Exception as exc:
            self._logger.warning(
                "Delayed LLM remediation generation failed for %s: %s",
                event_type,
                exc,
            )
            await self._record_failure(event_type=event_type, reason=str(exc))
            return

        await self._publish_message(
            event_type=event_type,
            alert=alert,
            suggestion=result.text,
            provider=result.provider,
            model=result.model_used,
            elapsed_seconds=monotonic() - started,
            delayed=True,
        )

    async def _publish_message(
        self,
        *,
        event_type: str,
        alert: OutboundMessage,
        suggestion: str,
        provider: str,
        model: str,
        elapsed_seconds: float,
        delayed: bool,
    ) -> None:
        clean_suggestion = suggestion.strip()
        if not clean_suggestion:
            await self._record_failure(
                event_type=event_type, reason="LLM returned an empty remediation suggestion."
            )
            return

        elapsed_display = f"{elapsed_seconds:.1f}s"
        follow_up_title = "🤖 AI remediation suggestion"
        if delayed:
            follow_up_title = "🤖 AI remediation suggestion (delayed)"
        alert_title = alert.title or event_type
        text = (
            f"Follow-up for **{alert_title}**.\n\n"
            "Advisory only — no automatic action has been taken.\n\n"
            f"{clean_suggestion[:2800]}\n\n"
            f"_Source: {provider}/{model} · generated in {elapsed_display}_"
        )
        await self._router.broadcast(
            OutboundMessage(
                title=follow_up_title,
                text=text,
                severity=AlertSeverity.INFO,
            )
        )
        await self._record_success(
            event_type=event_type,
            provider=provider,
            model=model,
            delayed=delayed,
            elapsed_seconds=elapsed_seconds,
            alert_title=alert_title,
        )

    def _build_prompt(self, *, event_type: str, payload: Any, alert: OutboundMessage) -> str:
        lines = [
            "You are generating remediation advice for a critical SystemSentinel alert.",
            "",
            f"Alert event type: {event_type}",
            f"Alert title: {alert.title or event_type}",
            f"Alert body: {alert.text}",
            "",
            "Alert metrics/details:",
        ]
        fields = alert.fields or {}
        if fields:
            for key, value in fields.items():
                lines.append(f"- {key}: {value}")
        elif isinstance(payload, dict):
            for key, value in payload.items():
                lines.append(f"- {key}: {value}")
        else:
            lines.append("- No structured fields available.")
        lines.extend(
            [
                "",
                "Recent system context:",
                runtime_context_summary(),
                "",
                "Return concise, step-by-step remediation guidance with explicit verification steps.",
            ]
        )
        return "\n".join(lines)

    async def _record_success(
        self,
        *,
        event_type: str,
        provider: str,
        model: str,
        delayed: bool,
        elapsed_seconds: float,
        alert_title: str,
    ) -> None:
        if self._audit is None:
            return
        await self._audit.append(
            action_type="llm_remediation",
            source=event_type,
            description=f"Published AI remediation suggestion for {alert_title}.",
            outcome="success",
            details={
                "provider": provider,
                "model": model,
                "delayed_follow_up": delayed,
                "elapsed_seconds": round(elapsed_seconds, 3),
            },
        )

    async def _record_failure(self, *, event_type: str, reason: str) -> None:
        if self._audit is None:
            return
        await self._audit.append(
            action_type="llm_remediation",
            source=event_type,
            description="Failed to generate AI remediation suggestion.",
            outcome="failure",
            details={"reason": reason},
        )

    def _track_background_task(self, task: asyncio.Task[None]) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)


def runtime_context_summary() -> str:
    lines: list[str] = []
    try:
        lines.append(f"- CPU percent: {psutil.cpu_percent(interval=None):.1f}")
    except psutil.Error:
        lines.append("- CPU percent: unavailable")
    try:
        lines.append(f"- RAM percent: {psutil.virtual_memory().percent:.1f}")
    except psutil.Error:
        lines.append("- RAM percent: unavailable")
    try:
        lines.append(f"- Disk percent (/): {psutil.disk_usage('/').percent:.1f}")
    except (psutil.Error, OSError):
        lines.append("- Disk percent (/): unavailable")
    try:
        load_1, load_5, load_15 = psutil.getloadavg()
        lines.append(f"- Load average: {load_1:.2f}, {load_5:.2f}, {load_15:.2f}")
    except (OSError, AttributeError):
        lines.append("- Load average: unavailable")
    return "\n".join(lines)
