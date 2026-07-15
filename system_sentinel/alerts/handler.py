from __future__ import annotations

import asyncio
import logging
from time import monotonic
from typing import TYPE_CHECKING, Any

import psutil

from system_sentinel.alerts.formatters import (
    _format_brute_force,
    _format_connection_daily_digest,
    _format_connection_repeat_threshold,
    _format_cpu_threshold_exceeded,
    _format_disk_threshold_exceeded,
    _format_firewall_drift,
    _format_impossible_travel,
    _format_network_threshold_exceeded,
    _format_new_user_login,
    _format_off_hours_login,
    _format_old_files_daily_digest,
    _format_ram_threshold_exceeded,
    _format_service_failure_detected,
    _format_service_restart_exhausted,
    _format_service_restart_result,
    _format_system_daily_digest,
    _format_unknown_connection,
)
from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.core.exceptions import LLMUnavailableError

if TYPE_CHECKING:
    from system_sentinel.chat.router import ChatRouter
    from system_sentinel.core.context import AuditRepository, LLMClient
    from system_sentinel.core.event_bus import InProcessEventBus

_EVENT_SEVERITY_KEYS = {
    "alert.cpu.threshold_exceeded": "cpu",
    "alert.ram.threshold_exceeded": "ram",
    "alert.disk.threshold_exceeded": "disk",
    "alert.network.throughput_threshold_exceeded": "network_throughput",
    "alert.login.brute_force_detected": "login",
    "alert.login.off_hours_detected": "login",
    "alert.login.new_user_detected": "login",
    "alert.login.impossible_travel_detected": "login",
    "alert.connection.unknown_ip_detected": "network_unknown_ip",
    "alert.connection.repeated_attempts_detected": "network_repeat",
    "alert.connection.daily_digest": "network_digest",
    "alert.files.daily_digest": "files_digest",
    "alert.service.failure_detected": "service_failure",
    "alert.service.restart_result": "service_restart_result",
    "alert.service.restart_exhausted": "service_restart_exhausted",
    "alert.firewall.drift_detected": "firewall_drift",
}

_SEVERITY_RANK: dict[AlertSeverity, int] = {
    AlertSeverity.INFO: 0,
    AlertSeverity.WARNING: 1,
    AlertSeverity.CRITICAL: 2,
}


def _coerce_severity(value: object) -> AlertSeverity | None:
    if not isinstance(value, str):
        return None
    lowered = value.strip().lower()
    if not lowered:
        return None
    try:
        return AlertSeverity(lowered)
    except ValueError:
        return None


def _coerce_positive_float(value: object, *, default: float) -> float:
    if isinstance(value, (int, float)):
        parsed = float(value)
        if parsed > 0:
            return parsed
    return default


def _with_severity(msg: OutboundMessage, severity: AlertSeverity) -> OutboundMessage:
    return OutboundMessage(
        title=msg.title,
        text=msg.text,
        severity=severity,
        fields=msg.fields,
        reply_to=msg.reply_to,
    )


class AlertHandler:
    """Subscribes to alert events on the event bus and forwards them to the ChatRouter."""

    def __init__(
        self,
        chat_router: ChatRouter,
        audit: AuditRepository | None = None,
        llm: LLMClient | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._router = chat_router
        self._audit = audit
        self._llm = llm
        self._logger = logging.getLogger("sentinel.alerts.handler")
        self._severity_levels: dict[str, AlertSeverity] = {}
        self._notify_min_severity = AlertSeverity.INFO
        self._llm_remediation_enabled = False
        self._llm_timeout_seconds = 30.0
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._load_config(config or {})

    def _load_config(self, config: dict[str, Any]) -> None:
        self._llm_remediation_enabled = bool(config.get("llm_remediation", False))
        llm_cfg = config.get("llm", {})
        if isinstance(llm_cfg, dict):
            self._llm_timeout_seconds = _coerce_positive_float(
                llm_cfg.get("timeout_seconds"), default=30.0
            )
        self._load_alert_config(config)

    def _load_alert_config(self, config: dict[str, Any]) -> None:
        alerts_cfg = config.get("alerts", {})
        if not isinstance(alerts_cfg, dict):
            return
        raw_levels = alerts_cfg.get("severity_levels", {})
        if isinstance(raw_levels, dict):
            for key, raw_value in raw_levels.items():
                if not isinstance(key, str):
                    continue
                severity = _coerce_severity(raw_value)
                if severity is None:
                    continue
                self._severity_levels[key.strip()] = severity
        min_severity = _coerce_severity(alerts_cfg.get("notify_min_severity"))
        if min_severity is not None:
            self._notify_min_severity = min_severity

    def register(self, event_bus: InProcessEventBus) -> None:
        """Wire this handler into *event_bus* by subscribing to known alert events."""
        event_bus.subscribe("alert.login.brute_force_detected", self._on_brute_force)
        event_bus.subscribe("alert.login.off_hours_detected", self._on_off_hours_login)
        event_bus.subscribe("alert.login.new_user_detected", self._on_new_user_login)
        event_bus.subscribe("alert.login.impossible_travel_detected", self._on_impossible_travel)
        event_bus.subscribe("alert.connection.unknown_ip_detected", self._on_unknown_connection)
        event_bus.subscribe(
            "alert.connection.repeated_attempts_detected",
            self._on_connection_repeat_threshold,
        )
        event_bus.subscribe("alert.connection.daily_digest", self._on_connection_daily_digest)
        event_bus.subscribe("alert.files.daily_digest", self._on_old_files_daily_digest)
        event_bus.subscribe("alert.system.daily_digest", self._on_system_daily_digest)
        event_bus.subscribe("alert.cpu.threshold_exceeded", self._on_cpu_threshold_exceeded)
        event_bus.subscribe("alert.ram.threshold_exceeded", self._on_ram_threshold_exceeded)
        event_bus.subscribe("alert.disk.threshold_exceeded", self._on_disk_threshold_exceeded)
        event_bus.subscribe(
            "alert.network.throughput_threshold_exceeded",
            self._on_network_threshold_exceeded,
        )
        event_bus.subscribe("alert.service.failure_detected", self._on_service_failure_detected)
        event_bus.subscribe("alert.service.restart_result", self._on_service_restart_result)
        event_bus.subscribe("alert.service.restart_exhausted", self._on_service_restart_exhausted)
        event_bus.subscribe("alert.firewall.drift_detected", self._on_firewall_drift)

    async def _on_unknown_connection(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Unknown inbound connection: %s → port %s/%s",
            payload.get("src_ip"),
            payload.get("dest_port"),
            payload.get("protocol"),
        )
        msg = self._apply_severity(event_type, payload, _format_unknown_connection(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_brute_force(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Brute-force alert from %s — %d attempt(s)",
            payload.get("ip_address"),
            payload.get("attempt_count", 0),
        )
        msg = self._apply_severity(event_type, payload, _format_brute_force(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_off_hours_login(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Off-hours login detected: user=%s ip=%s",
            payload.get("username"),
            payload.get("ip_address"),
        )
        msg = self._apply_severity(event_type, payload, _format_off_hours_login(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_new_user_login(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "New user login detected: user=%s ip=%s",
            payload.get("username"),
            payload.get("ip_address"),
        )
        msg = self._apply_severity(event_type, payload, _format_new_user_login(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_impossible_travel(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Impossible travel login detected: user=%s current=%s previous=%s",
            payload.get("username"),
            payload.get("ip_address"),
            payload.get("previous_ip_address"),
        )
        msg = self._apply_severity(event_type, payload, _format_impossible_travel(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_connection_repeat_threshold(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Repeated unknown connection attempts from %s — %d attempt(s)",
            payload.get("src_ip"),
            payload.get("attempt_count", 0),
        )
        msg = self._apply_severity(
            event_type, payload, _format_connection_repeat_threshold(payload)
        )
        await self._notify_and_record(event_type, payload, msg)

    async def _on_connection_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing daily unknown connection digest")
        msg = self._apply_severity(event_type, payload, _format_connection_daily_digest(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_old_files_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing daily old-files digest")
        msg = self._apply_severity(event_type, payload, _format_old_files_daily_digest(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_system_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing system daily digest")
        msg = _format_system_daily_digest(payload)
        await self._router.broadcast(msg)

    async def _on_cpu_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("CPU threshold exceeded: %s", payload.get("current_value"))
        msg = self._apply_severity(event_type, payload, _format_cpu_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_ram_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("RAM threshold exceeded: %s", payload.get("current_value"))
        msg = self._apply_severity(event_type, payload, _format_ram_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_disk_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning("Disk threshold exceeded: %s", payload.get("current_value"))
        msg = self._apply_severity(event_type, payload, _format_disk_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_network_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Network throughput threshold exceeded: sent=%s recv=%s",
            payload.get("bytes_sent"),
            payload.get("bytes_recv"),
        )
        msg = self._apply_severity(event_type, payload, _format_network_threshold_exceeded(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_service_failure_detected(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Service failure detected: %s is %s",
            payload.get("service_name"),
            payload.get("status"),
        )
        msg = self._apply_severity(event_type, payload, _format_service_failure_detected(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_service_restart_result(self, event_type: str, payload: Any) -> None:
        succeeded = bool(payload.get("succeeded", False))
        if succeeded:
            self._logger.info("Service restart succeeded: %s", payload.get("service_name"))
        else:
            self._logger.warning("Service restart failed: %s", payload.get("service_name"))
        msg = self._apply_severity(event_type, payload, _format_service_restart_result(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_service_restart_exhausted(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Service restart attempts exhausted: %s",
            payload.get("service_name"),
        )
        msg = self._apply_severity(event_type, payload, _format_service_restart_exhausted(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_firewall_drift(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Firewall drift detected: backend=%s missing=%s unexpected=%s",
            payload.get("backend"),
            len(payload.get("missing_rules", []))
            if isinstance(payload.get("missing_rules"), list)
            else 0,
            len(payload.get("unexpected_rules", []))
            if isinstance(payload.get("unexpected_rules"), list)
            else 0,
        )
        msg = self._apply_severity(event_type, payload, _format_firewall_drift(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _notify_and_record(self, event_type: str, payload: Any, msg: OutboundMessage) -> None:
        suppressed = _SEVERITY_RANK[msg.severity] < _SEVERITY_RANK[self._notify_min_severity]
        if not suppressed:
            await self._router.broadcast(msg)
        await self._record_alert(event_type, msg, suppressed=suppressed)
        if suppressed:
            return
        if msg.severity != AlertSeverity.CRITICAL:
            return
        await self._maybe_send_llm_remediation(event_type=event_type, payload=payload, alert=msg)

    def _apply_severity(
        self, event_type: str, payload: Any, msg: OutboundMessage
    ) -> OutboundMessage:
        override = None
        if isinstance(payload, dict):
            override = _coerce_severity(payload.get("severity_override"))
            if override is None:
                override = _coerce_severity(payload.get("rule_severity"))
        if override is not None:
            return _with_severity(msg, override)

        configured = self._severity_levels.get(event_type)
        if configured is None:
            alias = _EVENT_SEVERITY_KEYS.get(event_type)
            if alias is not None:
                configured = self._severity_levels.get(alias)
        if configured is None and isinstance(payload, dict):
            configured = _coerce_severity(payload.get("severity"))
        if configured is None:
            return msg
        return _with_severity(msg, configured)

    async def _record_alert(
        self,
        event_type: str,
        msg: OutboundMessage,
        *,
        suppressed: bool = False,
    ) -> None:
        if self._audit is None:
            return
        await self._audit.append(
            action_type="alert_fired",
            source=event_type,
            description=msg.title or event_type,
            outcome="success",
            details={
                "severity": msg.severity.value,
                "chat_notification_suppressed": suppressed,
            },
        )

    async def _maybe_send_llm_remediation(
        self,
        *,
        event_type: str,
        payload: Any,
        alert: OutboundMessage,
    ) -> None:
        llm_client = self._llm
        if not self._llm_remediation_enabled:
            return
        if llm_client is None or not llm_client.is_enabled:
            return

        system_prompt = (
            "You are SystemSentinel's remediation assistant. "
            "Provide concise, low-risk, actionable remediation steps. "
            "Do not suggest automatic execution and avoid destructive actions unless explicitly justified."
        )
        prompt = self._build_remediation_prompt(event_type=event_type, payload=payload, alert=alert)
        started = monotonic()
        request_task = asyncio.create_task(
            llm_client.complete(
                prompt=prompt,
                system_prompt=system_prompt,
                timeout_seconds=self._llm_timeout_seconds,
            )
        )
        try:
            result = await asyncio.wait_for(asyncio.shield(request_task), timeout=15.0)
        except TimeoutError:
            follow_up = asyncio.create_task(
                self._publish_delayed_remediation(
                    request_task=request_task,
                    event_type=event_type,
                    alert=alert,
                    started=started,
                )
            )
            self._track_background_task(follow_up)
            return
        except LLMUnavailableError as exc:
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return
        except Exception as exc:
            self._logger.warning(
                "LLM remediation generation failed for %s: %s",
                event_type,
                exc,
            )
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return

        await self._publish_llm_remediation_message(
            event_type=event_type,
            alert=alert,
            suggestion=result.text,
            provider=result.provider,
            model=result.model_used,
            elapsed_seconds=monotonic() - started,
            delayed=False,
        )

    async def _publish_delayed_remediation(
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
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return
        except Exception as exc:
            self._logger.warning(
                "Delayed LLM remediation generation failed for %s: %s",
                event_type,
                exc,
            )
            await self._record_llm_remediation_failure(event_type=event_type, reason=str(exc))
            return

        await self._publish_llm_remediation_message(
            event_type=event_type,
            alert=alert,
            suggestion=result.text,
            provider=result.provider,
            model=result.model_used,
            elapsed_seconds=monotonic() - started,
            delayed=True,
        )

    async def _publish_llm_remediation_message(
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
            await self._record_llm_remediation_failure(
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
        await self._record_llm_remediation_success(
            event_type=event_type,
            provider=provider,
            model=model,
            delayed=delayed,
            elapsed_seconds=elapsed_seconds,
            alert_title=alert_title,
        )

    def _build_remediation_prompt(
        self, *, event_type: str, payload: Any, alert: OutboundMessage
    ) -> str:
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
                self._runtime_context_summary(),
                "",
                "Return concise, step-by-step remediation guidance with explicit verification steps.",
            ]
        )
        return "\n".join(lines)

    def _runtime_context_summary(self) -> str:
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

    async def _record_llm_remediation_success(
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

    async def _record_llm_remediation_failure(self, *, event_type: str, reason: str) -> None:
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
