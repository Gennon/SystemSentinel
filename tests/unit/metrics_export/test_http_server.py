from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
import logging

import pytest

from system_sentinel.db.connection import DatabaseConnection
from system_sentinel.metrics_export.http_server import PrometheusExporterServer


@pytest.fixture
async def db() -> DatabaseConnection:
    conn = DatabaseConnection(":memory:")
    await conn.connect()
    yield conn
    await conn.close()


async def _seed_metrics(db: DatabaseConnection) -> None:
    now_iso = datetime.now(UTC).isoformat()
    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (now_iso, "cpu", json.dumps({"overall_percent": 61.5})),
    )
    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (now_iso, "ram", json.dumps({"percent": 72.25})),
    )
    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (
            now_iso,
            "disk",
            json.dumps(
                {
                    "partitions": [
                        {"mountpoint": "/", "percent": 55.0},
                        {"mountpoint": "/data", "percent": 88.0},
                    ]
                }
            ),
        ),
    )
    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (now_iso, "network", json.dumps({"bytes_sent": 1234, "bytes_recv": 4321})),
    )
    await db.connection.execute(
        "INSERT INTO system_metrics (timestamp, metric_type, data_json) VALUES (?, ?, ?)",
        (
            now_iso,
            "gpu",
            json.dumps(
                {
                    "vendor": "nvidia",
                    "utilization_percent": 42.0,
                    "temperature_c": 67.0,
                    "power_draw_w": 140.0,
                    "vram_used_mb": 2048.0,
                    "vram_total_mb": 8192.0,
                }
            ),
        ),
    )
    await db.connection.execute(
        """
        INSERT INTO login_attempts (timestamp, ip_address, username, port, host)
        VALUES (?, ?, ?, ?, ?)
        """,
        (now_iso, "203.0.113.9", "root", 22, "host-a"),
    )
    await db.connection.commit()


async def _request(port: int, request: str) -> str:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request.encode("utf-8"))
    await writer.drain()
    data = await reader.read(-1)
    writer.close()
    await writer.wait_closed()
    return data.decode("utf-8", errors="replace")


class TestPrometheusExporterServer:
    @pytest.mark.asyncio
    async def test_metrics_endpoint_returns_prometheus_text(self, db: DatabaseConnection) -> None:
        await _seed_metrics(db)
        exporter = PrometheusExporterServer(
            config={"enabled": True, "port": 0},
            app_config={"monitors": {"cpu": {"alert_threshold_percent": 90}}},
            db=db,
            logger=logging.getLogger("test.prometheus_exporter"),
        )
        await exporter.start()
        try:
            response = await _request(
                exporter.port,
                "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
        finally:
            await exporter.stop()

        assert "HTTP/1.1 200 OK" in response
        assert "text/plain; version=0.0.4; charset=utf-8" in response
        assert "system_sentinel_cpu_usage_percent 61.5" in response
        assert 'system_sentinel_disk_usage_percent{mountpoint="/"} 55.0' in response
        assert "system_sentinel_network_bytes_sent 1234.0" in response
        assert "system_sentinel_gpu_utilization_percent" in response
        assert "system_sentinel_login_failures_total 1.0" in response
        assert "system_sentinel_active_alerts 1.0" in response

    @pytest.mark.asyncio
    async def test_metrics_endpoint_requires_bearer_token_when_configured(
        self, db: DatabaseConnection
    ) -> None:
        exporter = PrometheusExporterServer(
            config={"enabled": True, "port": 0, "bearer_token": "secret-token"},
            app_config={},
            db=db,
            logger=logging.getLogger("test.prometheus_exporter"),
        )
        await exporter.start()
        try:
            denied = await _request(
                exporter.port,
                "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            allowed = await _request(
                exporter.port,
                (
                    "GET /metrics HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Authorization: Bearer secret-token\r\n"
                    "Connection: close\r\n\r\n"
                ),
            )
        finally:
            await exporter.stop()

        assert "HTTP/1.1 401 Unauthorized" in denied
        assert "WWW-Authenticate: Bearer" in denied
        assert "HTTP/1.1 200 OK" in allowed

    @pytest.mark.asyncio
    async def test_metrics_endpoint_only_serves_metrics_path(self, db: DatabaseConnection) -> None:
        exporter = PrometheusExporterServer(
            config={"enabled": True, "port": 0},
            app_config={},
            db=db,
            logger=logging.getLogger("test.prometheus_exporter"),
        )
        await exporter.start()
        try:
            response = await _request(
                exporter.port,
                "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
        finally:
            await exporter.stop()

        assert "HTTP/1.1 404 Not Found" in response


class TestPrometheusExporterConfig:
    @pytest.mark.asyncio
    async def test_exporter_disabled_does_not_bind_port(self, db: DatabaseConnection) -> None:
        exporter = PrometheusExporterServer(
            config={"enabled": False, "port": 9100},
            app_config={},
            db=db,
            logger=logging.getLogger("test.prometheus_exporter"),
        )
        await exporter.start()
        await exporter.stop()
        assert exporter.enabled is False

    @pytest.mark.asyncio
    async def test_port_defaults_when_config_is_invalid(self, db: DatabaseConnection) -> None:
        exporter = PrometheusExporterServer(
            config={"enabled": True, "port": "invalid"},
            app_config={},
            db=db,
            logger=logging.getLogger("test.prometheus_exporter"),
        )
        await exporter.start()
        try:
            assert isinstance(exporter.port, int)
        finally:
            await exporter.stop()
