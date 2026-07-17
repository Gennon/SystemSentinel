from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
import json
from typing import TYPE_CHECKING, Any

from system_sentinel.chat.command_metrics import get_active_alert_conditions

if TYPE_CHECKING:
    from collections.abc import Mapping
    import logging

    from system_sentinel.db.connection import DatabaseConnection

_DEFAULT_PORT = 9100
_DEFAULT_HOST = "0.0.0.0"
_MAX_REQUEST_BYTES = 16384


def _coerce_port(value: object) -> int:
    if isinstance(value, bool):
        return _DEFAULT_PORT
    if isinstance(value, int) and 0 <= value <= 65535:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        if 0 <= parsed <= 65535:
            return parsed
    return _DEFAULT_PORT


def _as_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return float(stripped)
        except ValueError:
            return None
    return None


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _sample_line(name: str, value: float, labels: Mapping[str, str] | None = None) -> str:
    if not labels:
        return f"{name} {value}"
    rendered = ",".join(f'{key}="{_escape_label(raw)}"' for key, raw in sorted(labels.items()))
    return f"{name}{{{rendered}}} {value}"


class PrometheusMetricsCollector:
    def __init__(self, *, db: DatabaseConnection, app_config: Mapping[str, Any]) -> None:
        self._db = db
        self._app_config = app_config

    async def collect_text(self) -> str:
        lines: list[str] = []
        append = lines.append

        append("# HELP system_sentinel_cpu_usage_percent Latest CPU usage percent.")
        append("# TYPE system_sentinel_cpu_usage_percent gauge")
        cpu = await self._latest_metric("cpu")
        if cpu is not None:
            cpu_percent = _as_float(cpu.get("overall_percent"))
            if cpu_percent is not None:
                append(_sample_line("system_sentinel_cpu_usage_percent", cpu_percent))

        append("# HELP system_sentinel_ram_usage_percent Latest RAM usage percent.")
        append("# TYPE system_sentinel_ram_usage_percent gauge")
        ram = await self._latest_metric("ram")
        if ram is not None:
            ram_percent = _as_float(ram.get("percent"))
            if ram_percent is not None:
                append(_sample_line("system_sentinel_ram_usage_percent", ram_percent))

        append(
            "# HELP system_sentinel_disk_usage_percent Latest disk usage percent per mountpoint."
        )
        append("# TYPE system_sentinel_disk_usage_percent gauge")
        disk = await self._latest_metric("disk")
        if disk is not None:
            partitions = disk.get("partitions")
            if isinstance(partitions, list):
                for partition in partitions:
                    if not isinstance(partition, dict):
                        continue
                    percent = _as_float(partition.get("percent"))
                    mountpoint = str(partition.get("mountpoint", "unknown"))
                    if percent is None:
                        continue
                    append(
                        _sample_line(
                            "system_sentinel_disk_usage_percent",
                            percent,
                            labels={"mountpoint": mountpoint},
                        )
                    )

        append("# HELP system_sentinel_network_bytes_sent Latest network bytes sent per interval.")
        append("# TYPE system_sentinel_network_bytes_sent gauge")
        append(
            "# HELP system_sentinel_network_bytes_recv Latest network bytes received per interval."
        )
        append("# TYPE system_sentinel_network_bytes_recv gauge")
        network = await self._latest_metric("network")
        if network is not None:
            bytes_sent = _as_float(network.get("bytes_sent"))
            bytes_recv = _as_float(network.get("bytes_recv"))
            if bytes_sent is not None:
                append(_sample_line("system_sentinel_network_bytes_sent", bytes_sent))
            if bytes_recv is not None:
                append(_sample_line("system_sentinel_network_bytes_recv", bytes_recv))

        append("# HELP system_sentinel_gpu_utilization_percent Latest GPU utilization percent.")
        append("# TYPE system_sentinel_gpu_utilization_percent gauge")
        append("# HELP system_sentinel_gpu_temperature_celsius Latest GPU temperature in Celsius.")
        append("# TYPE system_sentinel_gpu_temperature_celsius gauge")
        append("# HELP system_sentinel_gpu_power_draw_watts Latest GPU power draw in watts.")
        append("# TYPE system_sentinel_gpu_power_draw_watts gauge")
        append("# HELP system_sentinel_gpu_vram_used_megabytes Latest GPU VRAM used in MB.")
        append("# TYPE system_sentinel_gpu_vram_used_megabytes gauge")
        append("# HELP system_sentinel_gpu_vram_total_megabytes Latest GPU VRAM total in MB.")
        append("# TYPE system_sentinel_gpu_vram_total_megabytes gauge")
        gpu = await self._latest_metric("gpu")
        if gpu is not None:
            labels = {"vendor": str(gpu.get("vendor", "unknown"))}
            utilization = _as_float(gpu.get("utilization_percent"))
            temperature = _as_float(gpu.get("temperature_c"))
            power_draw = _as_float(gpu.get("power_draw_w"))
            vram_used = _as_float(gpu.get("vram_used_mb"))
            vram_total = _as_float(gpu.get("vram_total_mb"))
            if utilization is not None:
                append(
                    _sample_line(
                        "system_sentinel_gpu_utilization_percent", utilization, labels=labels
                    )
                )
            if temperature is not None:
                append(
                    _sample_line(
                        "system_sentinel_gpu_temperature_celsius", temperature, labels=labels
                    )
                )
            if power_draw is not None:
                append(
                    _sample_line("system_sentinel_gpu_power_draw_watts", power_draw, labels=labels)
                )
            if vram_used is not None:
                append(
                    _sample_line(
                        "system_sentinel_gpu_vram_used_megabytes", vram_used, labels=labels
                    )
                )
            if vram_total is not None:
                append(
                    _sample_line(
                        "system_sentinel_gpu_vram_total_megabytes", vram_total, labels=labels
                    )
                )

        append("# HELP system_sentinel_login_failures_total Total failed login attempts observed.")
        append("# TYPE system_sentinel_login_failures_total counter")
        append(
            _sample_line(
                "system_sentinel_login_failures_total", float(await self._login_failures_count())
            )
        )

        append("# HELP system_sentinel_active_alerts Number of currently active alert conditions.")
        append("# TYPE system_sentinel_active_alerts gauge")
        append(
            _sample_line("system_sentinel_active_alerts", float(await self._active_alert_count()))
        )
        append("")

        return "\n".join(lines)

    async def _latest_metric(self, metric_type: str) -> dict[str, Any] | None:
        cursor = await self._db.connection.execute(
            """
            SELECT data_json
            FROM system_metrics
            WHERE metric_type = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (metric_type,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        raw = row[0]
        if not isinstance(raw, str):
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    async def _login_failures_count(self) -> int:
        cursor = await self._db.connection.execute("SELECT COUNT(*) FROM login_attempts")
        row = await cursor.fetchone()
        if row is None:
            return 0
        return int(row[0])

    async def _active_alert_count(self) -> int:
        try:
            active_alerts = await get_active_alert_conditions(
                config=dict(self._app_config),
                db=self._db,
                now_iso=datetime.now(UTC).isoformat(),
            )
        except (TypeError, ValueError):
            return 0
        return len(active_alerts)


class PrometheusExporterServer:
    """Minimal async HTTP server that exposes Prometheus text metrics at ``/metrics``."""

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        app_config: Mapping[str, Any],
        db: DatabaseConnection,
        logger: logging.Logger,
    ) -> None:
        self._enabled = bool(config.get("enabled", False))
        self._port = _coerce_port(config.get("port"))
        self._token = self._coerce_token(config.get("bearer_token"))
        self._logger = logger
        self._collector = PrometheusMetricsCollector(db=db, app_config=app_config)
        self._server: asyncio.AbstractServer | None = None
        self._bound_port: int | None = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def port(self) -> int:
        return self._bound_port or self._port

    async def start(self) -> None:
        if not self._enabled:
            return
        self._server = await asyncio.start_server(self._handle_client, _DEFAULT_HOST, self._port)
        if self._server.sockets:
            socket_name = self._server.sockets[0].getsockname()
            if isinstance(socket_name, tuple) and len(socket_name) >= 2:
                self._bound_port = int(socket_name[1])
        self._logger.info(
            "Prometheus metrics exporter listening on %s:%d", _DEFAULT_HOST, self.port
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None
        self._logger.info("Prometheus metrics exporter stopped.")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request = await self._read_request(reader)
            if request is None:
                await self._send_response(
                    writer,
                    400,
                    "Bad Request",
                    "Malformed request.",
                )
                return
            method, path, headers = request
            if method != "GET":
                await self._send_response(
                    writer, 405, "Method Not Allowed", "Only GET is supported."
                )
                return
            if path != "/metrics":
                await self._send_response(writer, 404, "Not Found", "Unknown endpoint.")
                return
            if not self._is_authorized(headers):
                await self._send_response(
                    writer,
                    401,
                    "Unauthorized",
                    "Missing or invalid bearer token.",
                    extra_headers={"WWW-Authenticate": "Bearer"},
                )
                return
            payload = await self._collector.collect_text()
            await self._send_response(
                writer,
                200,
                "OK",
                payload,
                extra_headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
            )
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    async def _read_request(
        self,
        reader: asyncio.StreamReader,
    ) -> tuple[str, str, dict[str, str]] | None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2.0)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return None
        if len(raw) > _MAX_REQUEST_BYTES:
            return None
        try:
            decoded = raw.decode("latin-1")
        except UnicodeDecodeError:
            return None
        lines = decoded.split("\r\n")
        if not lines:
            return None
        request_line = lines[0].strip()
        parts = request_line.split()
        if len(parts) < 2:
            return None
        method = parts[0].upper()
        path = parts[1].split("?", maxsplit=1)[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" not in line:
                continue
            key, raw_value = line.split(":", maxsplit=1)
            headers[key.strip().lower()] = raw_value.strip()
        return method, path, headers

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status_code: int,
        status_text: str,
        body: str,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        headers = {
            "Content-Length": str(len(payload)),
            "Connection": "close",
            "Content-Type": "text/plain; charset=utf-8",
        }
        if extra_headers is not None:
            headers.update(dict(extra_headers))
        response = [f"HTTP/1.1 {status_code} {status_text}"]
        response.extend(f"{key}: {value}" for key, value in headers.items())
        response.append("")
        writer.write(("\r\n".join(response) + "\r\n").encode("utf-8") + payload)
        await writer.drain()

    def _is_authorized(self, headers: Mapping[str, str]) -> bool:
        if self._token is None:
            return True
        auth_header = headers.get("authorization")
        if auth_header is None:
            return False
        expected = f"Bearer {self._token}"
        return auth_header == expected

    def _coerce_token(self, raw: object) -> str | None:
        if not isinstance(raw, str):
            return None
        token = raw.strip()
        if not token:
            return None
        return token
