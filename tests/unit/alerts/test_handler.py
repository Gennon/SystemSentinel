from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock

import pytest

from system_sentinel.alerts.handler import (
    AlertHandler,
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
from system_sentinel.chat.base import AlertSeverity, OutboundMessage
from system_sentinel.chat.router import ChatRouter
from system_sentinel.core.event_bus import InProcessEventBus
from system_sentinel.llm.base import LLMResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_router() -> tuple[ChatRouter, list[OutboundMessage]]:
    """Return a ChatRouter wired to a recording adapter."""
    router = ChatRouter()
    broadcast_calls: list[OutboundMessage] = []

    class _RecordingAdapter:
        name = "recording"
        logger = logging.getLogger("test.recording")

        async def send_to_default(self, message: OutboundMessage) -> None:
            broadcast_calls.append(message)

        async def start(self) -> None: ...

        async def stop(self) -> None: ...

        async def send(self, channel_id: str, message: OutboundMessage) -> None: ...

    router.register(_RecordingAdapter())  # type: ignore[arg-type]
    return router, broadcast_calls


class _FakeRemediationLLMClient:
    def __init__(self) -> None:
        self.is_enabled = True
        self.active_provider_name = "ollama"
        self.calls = 0
        self.last_prompt: str | None = None
        self.last_timeout_seconds: float | None = None

    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMResponse:
        _ = system_prompt, model
        self.calls += 1
        self.last_prompt = prompt
        self.last_timeout_seconds = timeout_seconds
        return LLMResponse(
            text="1) Check load; 2) identify top process; 3) restart only if safe.",
            model_used="llama3.2",
            provider="ollama",
        )

    async def list_models(self) -> list[str]:
        return ["llama3.2"]

    async def health_check(self) -> bool:
        return True


class _DelayedRemediationLLMClient(_FakeRemediationLLMClient):
    def __init__(self, gate: asyncio.Event) -> None:
        super().__init__()
        self._gate = gate

    async def complete(
        self,
        *,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMResponse:
        await self._gate.wait()
        return await super().complete(
            prompt=prompt,
            system_prompt=system_prompt,
            model=model,
            timeout_seconds=timeout_seconds,
        )


_UNKNOWN_CONNECTION_PAYLOAD = {
    "src_ip": "8.8.8.8",
    "dest_port": 22,
    "protocol": "tcp",
    "timestamp": "2024-01-01T00:00:00+00:00",
}

_HARDENING_REMEDIATED_PAYLOAD = {
    "check_id": "sysctl_hardening",
    "title": "Kernel sysctl hardening",
    "details": "Mismatched sysctl values detected",
    "remediation": "Wrote /etc/sysctl.d/99-system-sentinel-hardening.conf and applied sysctl settings.",
}

_STORAGE_REPORT_PAYLOAD = {
    "event_type": "storage_report_generated",
    "generated_at": "2026-01-01T00:00:00+00:00",
    "paths": ["/"],
    "threshold_percent": 85,
    "flagged_paths": 1,
    "source": "scheduler",
    "report": "/: used=900 free=100 total=1000 (90.0%) status=ALERT threshold>85.0%",
}

_FILE_CHANGE_PAYLOAD = {
    "event_type": "directory_change_detected",
    "watched_directory": "/etc",
    "change_type": "modified",
    "file_path": "/etc/ssh/sshd_config",
    "timestamp": "2026-07-16T10:00:00+00:00",
    "process_owner": "root",
    "destination_path": None,
}


# ---------------------------------------------------------------------------
# _format_unknown_connection unit tests
# ---------------------------------------------------------------------------


def test_format_unknown_connection_title() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert "Unknown" in (msg.title or "")


def test_format_unknown_connection_severity_is_warning() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING


def test_format_unknown_connection_includes_src_ip() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert "8.8.8.8" in msg.text


def test_format_unknown_connection_includes_port_and_protocol() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert "22" in msg.text
    assert "tcp" in msg.text


def test_format_unknown_connection_fields_populated() -> None:
    msg = _format_unknown_connection(_UNKNOWN_CONNECTION_PAYLOAD)
    assert msg.fields is not None
    assert msg.fields["Source IP"] == "8.8.8.8"
    assert msg.fields["Destination Port"] == "22"


def test_format_firewall_drift_severity_is_warning() -> None:
    msg = _format_firewall_drift(_FIREWALL_DRIFT_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert "out of sync" in msg.text


def test_format_hardening_auto_remediated_severity_is_info() -> None:
    msg = _format_hardening_auto_remediated(_HARDENING_REMEDIATED_PAYLOAD)
    assert msg.severity == AlertSeverity.INFO
    assert "auto-remediated" in msg.text


def test_format_storage_report_uses_warning_when_paths_above_threshold() -> None:
    msg = _format_storage_report_generated(_STORAGE_REPORT_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert "status=ALERT" in msg.text


def test_format_file_change_detected_fields_present() -> None:
    msg = _format_file_change_detected(_FILE_CHANGE_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert msg.fields is not None
    assert msg.fields["Change Type"] == "modified"
    assert msg.fields["File Path"] == "/etc/ssh/sshd_config"
    assert msg.fields["Process Owner"] == "root"


# ---------------------------------------------------------------------------
# AlertHandler integration tests — unknown connection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handler_broadcasts_on_unknown_connection_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.unknown_ip_detected", _UNKNOWN_CONNECTION_PAYLOAD)

    assert len(calls) == 1
    assert "8.8.8.8" in calls[0].text


@pytest.mark.asyncio
async def test_handler_unknown_connection_message_severity_is_warning() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.unknown_ip_detected", _UNKNOWN_CONNECTION_PAYLOAD)

    assert calls[0].severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_handler_broadcasts_on_firewall_drift_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.firewall.drift_detected", _FIREWALL_DRIFT_PAYLOAD)

    assert len(calls) == 1
    assert "Firewall backend" in calls[0].text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_hardening_auto_remediated_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.hardening.auto_remediated", _HARDENING_REMEDIATED_PAYLOAD)

    assert len(calls) == 1
    assert "sysctl_hardening" in calls[0].text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_storage_report_generated_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.storage.report_generated", _STORAGE_REPORT_PAYLOAD)

    assert len(calls) == 1
    assert "status=ALERT" in calls[0].text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_file_change_detected_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.files.change_detected", _FILE_CHANGE_PAYLOAD)

    assert len(calls) == 1
    assert "sshd_config" in calls[0].text


_BRUTE_FORCE_PAYLOAD = {
    "ip_address": "1.2.3.4",
    "attempt_count": 7,
    "usernames": ["root", "admin", "ubuntu"],
    "window_minutes": 10,
}

_OFF_HOURS_PAYLOAD = {
    "anomaly_type": "off_hours",
    "event_type": "successful_ssh_login",
    "username": "alice",
    "ip_address": "8.8.8.8",
    "auth_method": "password",
    "port": 22,
    "timestamp": "2024-01-01T01:00:00+00:00",
    "hostname": "sentinel-host",
    "allowed_hours": "07:00-22:00",
}

_NEW_USER_PAYLOAD = {
    "anomaly_type": "new_user",
    "event_type": "successful_ssh_login",
    "username": "newadmin",
    "ip_address": "9.9.9.9",
    "auth_method": "publickey",
    "port": 22,
    "timestamp": "2024-01-01T12:00:00+00:00",
    "hostname": "sentinel-host",
}

_IMPOSSIBLE_TRAVEL_PAYLOAD = {
    "anomaly_type": "impossible_travel",
    "event_type": "successful_ssh_login",
    "username": "alice",
    "ip_address": "203.0.113.7",
    "previous_ip_address": "1.2.3.4",
    "distance_km": 8800.0,
    "window_minutes": 120,
    "timestamp": "2024-01-01T12:00:00+00:00",
    "previous_timestamp": "2024-01-01T11:20:00+00:00",
    "hostname": "sentinel-host",
}

_CONNECTION_REPEAT_PAYLOAD = {
    "src_ip": "8.8.8.8",
    "attempt_count": 4,
    "window_minutes": 10,
    "ports": [22, 80],
    "timestamp": "2024-01-01T00:00:00+00:00",
    "classification": {
        "category": "likely_access_attempt",
        "confidence": 0.91,
        "recommended_action": "block",
        "reasons": ["high_attempt_volume", "sensitive_port_targeted"],
    },
}

_CONNECTION_DAILY_DIGEST_PAYLOAD = {
    "timestamp": "2024-01-01T08:00:00+00:00",
    "period_hours": 24,
    "rows": [
        {"ip_address": "8.8.8.8", "dest_port": 22, "attempts": 3},
        {"ip_address": "1.2.3.4", "dest_port": 80, "attempts": 2},
    ],
}

_OLD_FILES_DAILY_DIGEST_PAYLOAD = {
    "timestamp": "2024-01-01T08:00:00+00:00",
    "period_hours": 24,
    "rows": [
        {"watched_directory": "/var/log", "file_count": 3, "total_size_bytes": 1200},
        {"watched_directory": "/tmp/archive", "file_count": 1, "total_size_bytes": 300},
    ],
}

_SYSTEM_DAILY_DIGEST_PAYLOAD = {
    "generated_at": "2024-01-01T08:00:00+00:00",
    "sections": {
        "System Uptime": "1d 02h",
        "Update Status": "Last run: 2024-01-01T02:00:00+00:00",
        "24h Resource Usage": "CPU avg 20%",
    },
}

_SYSTEM_WEEKLY_DIGEST_PAYLOAD = {
    "generated_at": "2024-01-08T08:00:00+00:00",
    "sections": {
        "Storage Usage Trend (7d)": "/: +4.2 GB, +12.0% vs last week",
        "Login Summary (7d)": "successful=14, failed=6, unique_ips=5, anomalies=2",
    },
}

_CPU_THRESHOLD_PAYLOAD = {
    "event_type": "cpu_threshold_exceeded",
    "current_value": "95.0%",
    "threshold": ">90.0% for more than 2 consecutive intervals",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "hostname": "sentinel-host",
}

_RAM_THRESHOLD_PAYLOAD = {
    "event_type": "ram_threshold_exceeded",
    "current_value": "92.0%",
    "threshold": ">90.0%",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "hostname": "sentinel-host",
}

_DISK_THRESHOLD_PAYLOAD = {
    "event_type": "disk_threshold_exceeded",
    "current_value": "91.0%",
    "threshold": ">85.0%",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "hostname": "sentinel-host",
    "mountpoint": "/",
    "device": "/dev/sda1",
}

_NETWORK_THRESHOLD_PAYLOAD = {
    "event_type": "network_throughput_threshold_exceeded",
    "bytes_sent": 1600000,
    "bytes_recv": 800000,
    "threshold": "sent>1000000 B/interval or recv>1000000 B/interval",
    "triggered_metrics": ["bytes_sent"],
    "timestamp": "2024-01-01T00:00:00+00:00",
    "hostname": "sentinel-host",
}

_GPU_THRESHOLD_PAYLOAD = {
    "event_type": "gpu_threshold_exceeded",
    "current_utilization_percent": "98.0%",
    "current_temperature_c": "86.0°C",
    "threshold": "util>95.0% or temp>85.0°C",
    "triggered_metrics": ["utilization", "temperature"],
    "vendor": "nvidia",
    "device_count": 1,
    "timestamp": "2024-01-01T00:00:00+00:00",
    "hostname": "sentinel-host",
}

_SERVICE_FAILURE_PAYLOAD = {
    "service_name": "nginx.service",
    "status": "failed",
    "attempt": 1,
    "max_attempts": 3,
    "last_journal_lines": "example error line",
}

_SERVICE_RESTART_RESULT_SUCCESS_PAYLOAD = {
    "service_name": "nginx.service",
    "attempt": 1,
    "max_attempts": 3,
    "succeeded": True,
    "status_after_restart": "active",
    "error": "",
}

_SERVICE_RESTART_RESULT_FAILURE_PAYLOAD = {
    "service_name": "nginx.service",
    "attempt": 2,
    "max_attempts": 3,
    "succeeded": False,
    "status_after_restart": "failed",
    "error": "permission denied",
}

_SERVICE_RESTART_EXHAUSTED_PAYLOAD = {
    "service_name": "nginx.service",
    "max_attempts": 3,
    "status_after_restart": "failed",
}

_FIREWALL_DRIFT_PAYLOAD = {
    "backend": "ufw",
    "missing_rules": [{"source": "any", "port": 22, "protocol": "tcp"}],
    "unexpected_rules": [{"source": "any", "port": 8080, "protocol": "tcp"}],
    "live_default_incoming_policy": "allow",
    "desired_default_incoming_policy": "deny",
    "enforce": False,
}


# ---------------------------------------------------------------------------
# _format_brute_force unit tests
# ---------------------------------------------------------------------------


def test_format_brute_force_title() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert "Brute Force" in (msg.title or "")


def test_format_brute_force_severity_is_critical() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert msg.severity == AlertSeverity.CRITICAL


def test_format_brute_force_includes_ip() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert "1.2.3.4" in msg.text


def test_format_brute_force_includes_attempt_count() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert "7" in msg.text


def test_format_brute_force_includes_all_usernames() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    for username in ["root", "admin", "ubuntu"]:
        assert username in msg.text


def test_format_brute_force_fields_populated() -> None:
    msg = _format_brute_force(_BRUTE_FORCE_PAYLOAD)
    assert msg.fields is not None
    assert msg.fields["IP Address"] == "1.2.3.4"
    assert msg.fields["Attempts"] == "7"
    assert msg.fields["Event Type"] == "failed_ssh_logins"
    assert msg.fields["Timestamp"] == "—"
    assert msg.fields["Hostname"] == "—"


def test_format_off_hours_login_fields_populated() -> None:
    msg = _format_off_hours_login(_OFF_HOURS_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert msg.fields is not None
    assert msg.fields["Anomaly Type"] == "off_hours"
    assert msg.fields["Username"] == "alice"


def test_format_new_user_login_fields_populated() -> None:
    msg = _format_new_user_login(_NEW_USER_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert msg.fields is not None
    assert msg.fields["Anomaly Type"] == "new_user"
    assert msg.fields["Username"] == "newadmin"


def test_format_impossible_travel_fields_populated() -> None:
    msg = _format_impossible_travel(_IMPOSSIBLE_TRAVEL_PAYLOAD)
    assert msg.severity == AlertSeverity.CRITICAL
    assert msg.fields is not None
    assert msg.fields["Anomaly Type"] == "impossible_travel"
    assert msg.fields["Current IP"] == "203.0.113.7"


# ---------------------------------------------------------------------------
# AlertHandler integration tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handler_broadcasts_on_brute_force_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.brute_force_detected", _BRUTE_FORCE_PAYLOAD)

    assert len(calls) == 1
    assert "1.2.3.4" in calls[0].text


@pytest.mark.asyncio
async def test_handler_does_not_broadcast_for_unrelated_events() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("metrics.cpu.high", {"value": 99})

    assert calls == []


@pytest.mark.asyncio
async def test_handler_message_includes_usernames() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.brute_force_detected", _BRUTE_FORCE_PAYLOAD)

    msg = calls[0]
    assert "root" in msg.text
    assert "admin" in msg.text


@pytest.mark.asyncio
async def test_handler_message_severity_is_critical() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.brute_force_detected", _BRUTE_FORCE_PAYLOAD)

    assert calls[0].severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_handler_broadcasts_on_off_hours_login_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.off_hours_detected", _OFF_HOURS_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING
    assert "alice" in calls[0].text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_new_user_login_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.new_user_detected", _NEW_USER_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING
    assert "newadmin" in calls[0].text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_impossible_travel_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.login.impossible_travel_detected", _IMPOSSIBLE_TRAVEL_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL
    assert "Impossible Travel" in (calls[0].title or "")


def test_format_connection_repeat_threshold_severity_is_critical() -> None:
    msg = _format_connection_repeat_threshold(_CONNECTION_REPEAT_PAYLOAD)
    assert msg.severity == AlertSeverity.CRITICAL


def test_format_connection_repeat_threshold_includes_ports() -> None:
    msg = _format_connection_repeat_threshold(_CONNECTION_REPEAT_PAYLOAD)
    assert "22" in msg.text
    assert "80" in msg.text


def test_format_connection_repeat_threshold_includes_classification_details() -> None:
    msg = _format_connection_repeat_threshold(_CONNECTION_REPEAT_PAYLOAD)
    assert "likely_access_attempt" in msg.text
    assert msg.fields is not None
    assert msg.fields["Classification"] == "likely_access_attempt"
    assert msg.fields["Recommended Action"] == "block"


@pytest.mark.asyncio
async def test_handler_broadcasts_on_connection_repeat_threshold_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.repeated_attempts_detected", _CONNECTION_REPEAT_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL
    assert "8.8.8.8" in calls[0].text


def test_format_connection_daily_digest_fields() -> None:
    msg = _format_connection_daily_digest(_CONNECTION_DAILY_DIGEST_PAYLOAD)
    assert msg.fields is not None
    assert msg.fields["Unique IPs"] == "2"
    assert msg.fields["Unique Ports"] == "2"
    assert msg.fields["Total Attempts"] == "5"


@pytest.mark.asyncio
async def test_handler_broadcasts_on_connection_daily_digest_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.daily_digest", _CONNECTION_DAILY_DIGEST_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING
    assert "8.8.8.8" in calls[0].text


def test_format_old_files_daily_digest_fields() -> None:
    msg = _format_old_files_daily_digest(_OLD_FILES_DAILY_DIGEST_PAYLOAD)
    assert msg.fields is not None
    assert msg.fields["Watched Directories"] == "2"
    assert msg.fields["Files Found"] == "4"
    assert msg.fields["Total Size (bytes)"] == "1500"


@pytest.mark.asyncio
async def test_handler_broadcasts_on_old_files_daily_digest_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.files.daily_digest", _OLD_FILES_DAILY_DIGEST_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.INFO
    assert "/var/log" in calls[0].text


def test_format_system_daily_digest_fields() -> None:
    msg = _format_system_daily_digest(_SYSTEM_DAILY_DIGEST_PAYLOAD)
    assert msg.title == "🧭 Daily System Digest"
    assert msg.fields is not None
    assert msg.fields["Timestamp"] == "2024-01-01T08:00:00+00:00"
    assert msg.fields["System Uptime"] == "1d 02h"


@pytest.mark.asyncio
async def test_handler_broadcasts_on_system_daily_digest_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.system.daily_digest", _SYSTEM_DAILY_DIGEST_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].title == "🧭 Daily System Digest"


def test_format_system_weekly_digest_fields() -> None:
    msg = _format_system_weekly_digest(_SYSTEM_WEEKLY_DIGEST_PAYLOAD)
    assert msg.title == "📈 Weekly System Trend Summary"
    assert msg.fields is not None
    assert msg.fields["Timestamp"] == "2024-01-08T08:00:00+00:00"
    assert "Storage Usage Trend (7d)" in msg.fields


@pytest.mark.asyncio
async def test_handler_broadcasts_on_system_weekly_digest_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.system.weekly_digest", _SYSTEM_WEEKLY_DIGEST_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].title == "📈 Weekly System Trend Summary"


@pytest.mark.asyncio
async def test_handler_audits_alert_event() -> None:
    router, _ = _make_router()
    audit = AsyncMock()
    audit.append = AsyncMock()
    handler = AlertHandler(router, audit=audit)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.connection.unknown_ip_detected", _UNKNOWN_CONNECTION_PAYLOAD)

    audit.append.assert_awaited_once()


def test_format_cpu_threshold_fields_present() -> None:
    msg = _format_cpu_threshold_exceeded(_CPU_THRESHOLD_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert msg.fields is not None
    assert msg.fields["Event Type"] == "cpu_threshold_exceeded"
    assert msg.fields["Current Value"] == "95.0%"
    assert msg.fields["Threshold"] == ">90.0% for more than 2 consecutive intervals"
    assert msg.fields["Timestamp"] == "2024-01-01T00:00:00+00:00"
    assert msg.fields["Hostname"] == "sentinel-host"


def test_format_ram_threshold_fields_present() -> None:
    msg = _format_ram_threshold_exceeded(_RAM_THRESHOLD_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert msg.fields is not None
    assert msg.fields["Event Type"] == "ram_threshold_exceeded"


def test_format_disk_threshold_fields_present() -> None:
    msg = _format_disk_threshold_exceeded(_DISK_THRESHOLD_PAYLOAD)
    assert msg.severity == AlertSeverity.CRITICAL
    assert msg.fields is not None
    assert msg.fields["Event Type"] == "disk_threshold_exceeded"
    assert msg.fields["Mountpoint"] == "/"
    assert msg.fields["Device"] == "/dev/sda1"


def test_format_network_threshold_fields_present() -> None:
    msg = _format_network_threshold_exceeded(_NETWORK_THRESHOLD_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert msg.fields is not None
    assert msg.fields["Event Type"] == "network_throughput_threshold_exceeded"
    assert msg.fields["Bytes Sent"] == "1600000"
    assert msg.fields["Bytes Received"] == "800000"
    assert msg.fields["Triggered Metrics"] == "bytes_sent"


def test_format_gpu_threshold_fields_present() -> None:
    msg = _format_gpu_threshold_exceeded(_GPU_THRESHOLD_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert msg.fields is not None
    assert msg.fields["Event Type"] == "gpu_threshold_exceeded"
    assert msg.fields["Current Utilization"] == "98.0%"
    assert msg.fields["Current Temperature"] == "86.0°C"
    assert msg.fields["Triggered Metrics"] == "utilization, temperature"
    assert msg.fields["Vendor"] == "nvidia"


@pytest.mark.asyncio
async def test_handler_broadcasts_on_cpu_threshold_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)
    await bus.publish("alert.cpu.threshold_exceeded", _CPU_THRESHOLD_PAYLOAD)
    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_handler_broadcasts_on_ram_threshold_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)
    await bus.publish("alert.ram.threshold_exceeded", _RAM_THRESHOLD_PAYLOAD)
    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_handler_broadcasts_on_disk_threshold_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)
    await bus.publish("alert.disk.threshold_exceeded", _DISK_THRESHOLD_PAYLOAD)
    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_handler_broadcasts_on_network_threshold_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)
    await bus.publish("alert.network.throughput_threshold_exceeded", _NETWORK_THRESHOLD_PAYLOAD)
    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_handler_broadcasts_on_gpu_threshold_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)
    await bus.publish("alert.gpu.threshold_exceeded", _GPU_THRESHOLD_PAYLOAD)
    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING


def test_format_service_failure_detected_includes_logs() -> None:
    msg = _format_service_failure_detected(_SERVICE_FAILURE_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert "nginx.service" in msg.text
    assert "example error line" in msg.text


def test_format_service_restart_result_success_is_info() -> None:
    msg = _format_service_restart_result(_SERVICE_RESTART_RESULT_SUCCESS_PAYLOAD)
    assert msg.severity == AlertSeverity.INFO
    assert "succeeded" in msg.text


def test_format_service_restart_result_failure_is_warning() -> None:
    msg = _format_service_restart_result(_SERVICE_RESTART_RESULT_FAILURE_PAYLOAD)
    assert msg.severity == AlertSeverity.WARNING
    assert "permission denied" in msg.text


def test_format_service_restart_exhausted_is_critical() -> None:
    msg = _format_service_restart_exhausted(_SERVICE_RESTART_EXHAUSTED_PAYLOAD)
    assert msg.severity == AlertSeverity.CRITICAL
    assert "did not recover" in msg.text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_service_failure_detected_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.service.failure_detected", _SERVICE_FAILURE_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING
    assert "nginx.service" in calls[0].text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_service_restart_result_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.service.restart_result", _SERVICE_RESTART_RESULT_SUCCESS_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.INFO
    assert "succeeded" in calls[0].text


@pytest.mark.asyncio
async def test_handler_broadcasts_on_service_restart_exhausted_event() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.service.restart_exhausted", _SERVICE_RESTART_EXHAUSTED_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL
    assert "did not recover" in calls[0].text


@pytest.mark.asyncio
async def test_handler_uses_configured_alert_severity_by_type() -> None:
    router, calls = _make_router()
    handler = AlertHandler(
        router,
        config={"alerts": {"severity_levels": {"cpu": "critical"}}},
    )
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.cpu.threshold_exceeded", _CPU_THRESHOLD_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_handler_suppresses_chat_below_min_severity_but_audits() -> None:
    router, calls = _make_router()
    audit = AsyncMock()
    handler = AlertHandler(
        router,
        audit=audit,
        config={
            "alerts": {
                "severity_levels": {"cpu": "warning"},
                "notify_min_severity": "critical",
            }
        },
    )
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.cpu.threshold_exceeded", _CPU_THRESHOLD_PAYLOAD)

    assert calls == []
    audit.append.assert_awaited_once()
    details = audit.append.call_args.kwargs["details"]
    assert details["severity"] == "warning"
    assert details["chat_notification_suppressed"] is True


@pytest.mark.asyncio
async def test_handler_rule_override_severity_takes_precedence() -> None:
    router, calls = _make_router()
    handler = AlertHandler(
        router,
        config={"alerts": {"severity_levels": {"cpu": "info"}}},
    )
    bus = InProcessEventBus()
    handler.register(bus)

    payload = dict(_CPU_THRESHOLD_PAYLOAD)
    payload["severity_override"] = "critical"
    await bus.publish("alert.cpu.threshold_exceeded", payload)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_handler_queues_non_critical_alerts_during_quiet_hours_and_flushes_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router, calls = _make_router()
    handler = AlertHandler(router, config={"alerts": {"quiet_hours": "00:00-00:00"}})
    bus = InProcessEventBus()
    handler.register(bus)

    monkeypatch.setattr("system_sentinel.alerts.handler.quiet_hours_end", lambda now, window: now)
    original_sleep = asyncio.sleep

    async def _no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr("system_sentinel.alerts.handler.asyncio.sleep", _no_wait)

    await bus.publish("alert.cpu.threshold_exceeded", _CPU_THRESHOLD_PAYLOAD)
    await original_sleep(0)

    assert len(calls) == 1
    assert calls[0].title == "🌙 Quiet hours ended"
    assert "Queued alerts during quiet hours: 1" in calls[0].text


@pytest.mark.asyncio
async def test_handler_critical_alert_bypasses_quiet_hours() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router, config={"alerts": {"quiet_hours": "00:00-00:00"}})
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.disk.threshold_exceeded", _DISK_THRESHOLD_PAYLOAD)

    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_handler_mute_suppresses_non_critical_until_unmuted() -> None:
    router, calls = _make_router()
    handler = AlertHandler(router)
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("chat.alerts.mute", {"duration_seconds": 3600})
    await bus.publish("alert.cpu.threshold_exceeded", _CPU_THRESHOLD_PAYLOAD)
    assert calls == []

    await bus.publish("alert.disk.threshold_exceeded", _DISK_THRESHOLD_PAYLOAD)
    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.CRITICAL

    await bus.publish("chat.alerts.unmute", {})
    await bus.publish("alert.cpu.threshold_exceeded", _CPU_THRESHOLD_PAYLOAD)

    assert len(calls) == 2
    assert calls[1].severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_handler_adds_ai_remediation_follow_up_for_critical_alerts() -> None:
    router, calls = _make_router()
    llm = _FakeRemediationLLMClient()
    handler = AlertHandler(router, llm=llm, config={"llm": {"remediation": True}})
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.disk.threshold_exceeded", _DISK_THRESHOLD_PAYLOAD)

    assert llm.calls == 1
    assert llm.last_timeout_seconds == 30.0
    assert llm.last_prompt is not None
    assert "Alert event type: alert.disk.threshold_exceeded" in llm.last_prompt
    assert "Alert metrics/details:" in llm.last_prompt
    assert "Recent system context:" in llm.last_prompt
    assert len(calls) == 2
    assert calls[0].title == "🔴 Disk Usage Critical"
    assert calls[1].title == "🤖 AI remediation suggestion"
    assert "Advisory only" in calls[1].text


@pytest.mark.asyncio
async def test_handler_does_not_call_llm_when_remediation_disabled() -> None:
    router, calls = _make_router()
    llm = _FakeRemediationLLMClient()
    handler = AlertHandler(router, llm=llm, config={"llm": {"remediation": False}})
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.disk.threshold_exceeded", _DISK_THRESHOLD_PAYLOAD)

    assert llm.calls == 0
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_handler_does_not_call_llm_for_non_critical_alerts() -> None:
    router, calls = _make_router()
    llm = _FakeRemediationLLMClient()
    handler = AlertHandler(router, llm=llm, config={"llm": {"remediation": True}})
    bus = InProcessEventBus()
    handler.register(bus)

    await bus.publish("alert.cpu.threshold_exceeded", _CPU_THRESHOLD_PAYLOAD)

    assert llm.calls == 0
    assert len(calls) == 1
    assert calls[0].severity == AlertSeverity.WARNING


@pytest.mark.asyncio
async def test_handler_sends_delayed_ai_follow_up_when_generation_exceeds_15_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router, calls = _make_router()
    gate = asyncio.Event()
    llm = _DelayedRemediationLLMClient(gate)
    handler = AlertHandler(router, llm=llm, config={"llm": {"remediation": True}})
    bus = InProcessEventBus()
    handler.register(bus)

    original_wait_for = asyncio.wait_for

    async def _patched_wait_for(awaitable: object, timeout: float) -> object:
        if timeout == 15.0:
            raise TimeoutError
        return await original_wait_for(awaitable, timeout)

    monkeypatch.setattr("system_sentinel.alerts.handler.asyncio.wait_for", _patched_wait_for)

    await bus.publish("alert.disk.threshold_exceeded", _DISK_THRESHOLD_PAYLOAD)
    assert len(calls) == 1

    gate.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert llm.calls == 1
    assert len(calls) == 2
    assert calls[1].title == "🤖 AI remediation suggestion (delayed)"
