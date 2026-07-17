from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import logging
from typing import TYPE_CHECKING, Any

from system_sentinel.alerts.formatters import (
    _format_brute_force,
    _format_connection_daily_digest,
    _format_connection_repeat_threshold,
    _format_cpu_threshold_exceeded,
    _format_disk_threshold_exceeded,
    _format_file_change_detected,
    _format_firewall_drift,
    _format_gpu_threshold_exceeded,
    _format_hardening_auto_remediated,
    _format_impossible_travel,
    _format_network_threshold_exceeded,
    _format_new_user_login,
    _format_off_hours_login,
    _format_old_files_daily_digest,
    _format_ram_threshold_exceeded,
    _format_service_failure_detected,
    _format_service_restart_exhausted,
    _format_service_restart_result,
    _format_storage_report_generated,
    _format_system_daily_digest,
    _format_system_weekly_digest,
    _format_unknown_connection,
)
from system_sentinel.alerts.quiet_hours import (
    QuietHoursWindow,
    parse_quiet_hours_window,
    quiet_hours_end,
)
from system_sentinel.alerts.remediation import AlertLLMRemediationService
from system_sentinel.chat.base import AlertSeverity, OutboundMessage

if TYPE_CHECKING:
    from system_sentinel.chat.router import ChatRouter
    from system_sentinel.core.context import AuditRepository, LLMClient
    from system_sentinel.core.event_bus import InProcessEventBus

_EVENT_SEVERITY_KEYS = {
    "alert.cpu.threshold_exceeded": "cpu",
    "alert.ram.threshold_exceeded": "ram",
    "alert.disk.threshold_exceeded": "disk",
    "alert.network.throughput_threshold_exceeded": "network_throughput",
    "alert.gpu.threshold_exceeded": "gpu",
    "alert.login.brute_force_detected": "login",
    "alert.login.off_hours_detected": "login",
    "alert.login.new_user_detected": "login",
    "alert.login.impossible_travel_detected": "login",
    "alert.connection.unknown_ip_detected": "network_unknown_ip",
    "alert.connection.repeated_attempts_detected": "network_repeat",
    "alert.connection.daily_digest": "network_digest",
    "alert.files.daily_digest": "files_digest",
    "alert.files.change_detected": "files_change",
    "alert.service.failure_detected": "service_failure",
    "alert.service.restart_result": "service_restart_result",
    "alert.service.restart_exhausted": "service_restart_exhausted",
    "alert.firewall.drift_detected": "firewall_drift",
    "alert.hardening.auto_remediated": "hardening",
    "alert.storage.report_generated": "storage_report",
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
        self._quiet_hours: QuietHoursWindow | None = None
        self._quiet_alert_queue: list[OutboundMessage] = []
        self._quiet_alert_flush_task: asyncio.Task[None] | None = None
        self._mute_until: datetime | None = None
        self._llm_remediation_enabled = False
        self._llm_timeout_seconds = 30.0
        self._load_config(config or {})
        self._llm_remediation = AlertLLMRemediationService(
            router=self._router,
            audit=self._audit,
            llm=self._llm,
            logger=self._logger,
            enabled=self._llm_remediation_enabled,
            timeout_seconds=self._llm_timeout_seconds,
        )

    def _load_config(self, config: dict[str, Any]) -> None:
        llm_cfg = config.get("llm", {})
        if isinstance(llm_cfg, dict):
            self._llm_remediation_enabled = bool(
                llm_cfg.get("remediation", config.get("llm_remediation", False))
            )
            self._llm_timeout_seconds = _coerce_positive_float(
                llm_cfg.get("timeout_seconds"), default=30.0
            )
        else:
            self._llm_remediation_enabled = bool(config.get("llm_remediation", False))
        self._load_alert_config(config)

    def _load_alert_config(self, config: dict[str, Any]) -> None:
        alerts_cfg = config.get("alerts", {})
        if isinstance(alerts_cfg, dict):
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
            quiet_hours = parse_quiet_hours_window(alerts_cfg.get("quiet_hours"))
        else:
            quiet_hours = None
        if quiet_hours is None:
            top_level_quiet_hours = parse_quiet_hours_window(config.get("quiet_hours"))
            if top_level_quiet_hours is not None:
                quiet_hours = top_level_quiet_hours
        self._quiet_hours = quiet_hours

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
        event_bus.subscribe("alert.files.change_detected", self._on_file_change_detected)
        event_bus.subscribe("alert.system.daily_digest", self._on_system_daily_digest)
        event_bus.subscribe("alert.system.weekly_digest", self._on_system_weekly_digest)
        event_bus.subscribe("alert.storage.report_generated", self._on_storage_report_generated)
        event_bus.subscribe("alert.cpu.threshold_exceeded", self._on_cpu_threshold_exceeded)
        event_bus.subscribe("alert.ram.threshold_exceeded", self._on_ram_threshold_exceeded)
        event_bus.subscribe("alert.disk.threshold_exceeded", self._on_disk_threshold_exceeded)
        event_bus.subscribe(
            "alert.network.throughput_threshold_exceeded",
            self._on_network_threshold_exceeded,
        )
        event_bus.subscribe("alert.gpu.threshold_exceeded", self._on_gpu_threshold_exceeded)
        event_bus.subscribe("alert.service.failure_detected", self._on_service_failure_detected)
        event_bus.subscribe("alert.service.restart_result", self._on_service_restart_result)
        event_bus.subscribe("alert.service.restart_exhausted", self._on_service_restart_exhausted)
        event_bus.subscribe("alert.firewall.drift_detected", self._on_firewall_drift)
        event_bus.subscribe("alert.hardening.auto_remediated", self._on_hardening_auto_remediated)
        event_bus.subscribe("chat.alerts.mute", self._on_mute_non_critical)
        event_bus.subscribe("chat.alerts.unmute", self._on_unmute_non_critical)

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

    async def _on_file_change_detected(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "Directory change detected: type=%s path=%s",
            payload.get("change_type"),
            payload.get("file_path"),
        )
        msg = self._apply_severity(event_type, payload, _format_file_change_detected(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_system_daily_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing system daily digest")
        msg = _format_system_daily_digest(payload)
        await self._router.broadcast(msg)

    async def _on_system_weekly_digest(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing system weekly digest")
        msg = _format_system_weekly_digest(payload)
        await self._router.broadcast(msg)

    async def _on_storage_report_generated(self, event_type: str, payload: Any) -> None:
        self._logger.info("Publishing scheduled storage report")
        msg = self._apply_severity(event_type, payload, _format_storage_report_generated(payload))
        await self._notify_and_record(event_type, payload, msg)

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

    async def _on_gpu_threshold_exceeded(self, event_type: str, payload: Any) -> None:
        self._logger.warning(
            "GPU threshold exceeded: util=%s temp=%s",
            payload.get("current_utilization_percent"),
            payload.get("current_temperature_c"),
        )
        msg = self._apply_severity(event_type, payload, _format_gpu_threshold_exceeded(payload))
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

    async def _on_hardening_auto_remediated(self, event_type: str, payload: Any) -> None:
        self._logger.info(
            "Hardening check auto-remediated: %s",
            payload.get("check_id"),
        )
        msg = self._apply_severity(event_type, payload, _format_hardening_auto_remediated(payload))
        await self._notify_and_record(event_type, payload, msg)

    async def _on_mute_non_critical(self, _event_type: str, payload: Any) -> None:
        mute_until = None
        if isinstance(payload, dict):
            raw_mute_until = payload.get("mute_until")
            if isinstance(raw_mute_until, str) and raw_mute_until.strip():
                try:
                    parsed = datetime.fromisoformat(raw_mute_until)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=UTC)
                    mute_until = parsed.astimezone(UTC)
                except ValueError:
                    mute_until = None
            if mute_until is None:
                duration_raw = payload.get("duration_seconds")
                if isinstance(duration_raw, (int, float)) and float(duration_raw) > 0:
                    mute_until = datetime.now(UTC) + timedelta(seconds=float(duration_raw))
        self._mute_until = mute_until

    async def _on_unmute_non_critical(self, _event_type: str, _payload: Any) -> None:
        self._mute_until = None

    async def _notify_and_record(self, event_type: str, payload: Any, msg: OutboundMessage) -> None:
        suppressed = _SEVERITY_RANK[msg.severity] < _SEVERITY_RANK[self._notify_min_severity]
        if (
            not suppressed
            and msg.severity != AlertSeverity.CRITICAL
            and self._is_non_critical_muted()
        ):
            suppressed = True
        if (
            not suppressed
            and msg.severity != AlertSeverity.CRITICAL
            and self._is_quiet_hours_active()
            and self._quiet_hours is not None
        ):
            suppressed = True
            self._quiet_alert_queue.append(msg)
            self._ensure_quiet_alert_flush_scheduled()
        if not suppressed:
            await self._router.broadcast(msg)
        await self._record_alert(event_type, msg, suppressed=suppressed)
        if suppressed:
            return
        if msg.severity != AlertSeverity.CRITICAL:
            return
        await self._llm_remediation.maybe_send(
            event_type=event_type,
            payload=payload,
            alert=msg,
            wait_for_fn=asyncio.wait_for,
        )

    def _is_non_critical_muted(self) -> bool:
        if self._mute_until is None:
            return False
        if datetime.now(UTC) < self._mute_until:
            return True
        self._mute_until = None
        return False

    def _is_quiet_hours_active(self) -> bool:
        if self._quiet_hours is None:
            return False
        return self._quiet_hours.is_active(datetime.now(UTC))

    def _ensure_quiet_alert_flush_scheduled(self) -> None:
        if self._quiet_hours is None:
            return
        task = self._quiet_alert_flush_task
        if task is not None and not task.done():
            return
        now = datetime.now(UTC)
        quiet_ends = quiet_hours_end(now, self._quiet_hours)
        delay_seconds = max(0.0, (quiet_ends - now).total_seconds())
        self._quiet_alert_flush_task = asyncio.create_task(
            self._flush_quiet_alerts_after_delay(delay_seconds)
        )

    async def _flush_quiet_alerts_after_delay(self, delay_seconds: float) -> None:
        try:
            await asyncio.sleep(delay_seconds)
            await self._flush_quiet_alert_queue()
        finally:
            self._quiet_alert_flush_task = None

    async def _flush_quiet_alert_queue(self) -> None:
        if not self._quiet_alert_queue:
            return
        queued = list(self._quiet_alert_queue)
        self._quiet_alert_queue.clear()
        warning_count = sum(1 for msg in queued if msg.severity == AlertSeverity.WARNING)
        info_count = sum(1 for msg in queued if msg.severity == AlertSeverity.INFO)
        lines = [
            f"Queued alerts during quiet hours: {len(queued)}",
            f"warning={warning_count}, info={info_count}",
            "",
        ]
        for index, queued_msg in enumerate(queued, start=1):
            label = queued_msg.severity.value.upper()
            first_line = (
                queued_msg.text.strip().splitlines()[0] if queued_msg.text.strip() else "No details"
            )
            lines.append(f"{index}. [{label}] {first_line}")
        digest_severity = AlertSeverity.WARNING if warning_count > 0 else AlertSeverity.INFO
        digest = OutboundMessage(
            title="🌙 Quiet hours ended",
            text="\n".join(lines),
            severity=digest_severity,
        )
        await self._router.broadcast(digest)
        await self._record_alert("alert.quiet_hours.digest", digest, suppressed=False)

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
