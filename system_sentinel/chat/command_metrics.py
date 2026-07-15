from __future__ import annotations

import json
from typing import Any


async def get_active_alert_conditions(
    *,
    config: dict[str, Any],
    db: Any,
    now_iso: str,
) -> list[str]:
    conditions: list[str] = []
    monitors_cfg = config.get("monitors", {})

    cpu_threshold = float(monitors_cfg.get("cpu", {}).get("alert_threshold_percent", 90))
    ram_threshold = float(monitors_cfg.get("ram", {}).get("alert_threshold_percent", 90))
    disk_threshold = float(monitors_cfg.get("disk", {}).get("alert_threshold_percent", 85))
    network_cfg = monitors_cfg.get("network", {})
    network_sent_threshold_raw = network_cfg.get("alert_threshold_bytes_sent")
    network_recv_threshold_raw = network_cfg.get("alert_threshold_bytes_recv")
    network_sent_threshold = (
        float(network_sent_threshold_raw) if network_sent_threshold_raw is not None else None
    )
    network_recv_threshold = (
        float(network_recv_threshold_raw) if network_recv_threshold_raw is not None else None
    )
    gpu_cfg = monitors_cfg.get("gpu", {})
    gpu_utilization_threshold = float(gpu_cfg.get("alert_threshold_utilization_percent", 95))
    gpu_temperature_threshold = float(gpu_cfg.get("alert_threshold_temperature_c", 85))

    cursor = await db.connection.execute(
        """
        SELECT metric_type, data_json
        FROM system_metrics
        WHERE id IN (
            SELECT MAX(id) FROM system_metrics GROUP BY metric_type
        )
        """
    )
    rows = await cursor.fetchall()
    latest_by_type = {str(row[0]): str(row[1]) for row in rows}

    if "cpu" in latest_by_type:
        cpu_data = json.loads(latest_by_type["cpu"])
        cpu_current = float(cpu_data.get("overall_percent", 0.0))
        if cpu_current > cpu_threshold:
            conditions.append(f"CPU high: {cpu_current:.1f}% > {cpu_threshold:.1f}% ({now_iso})")

    if "ram" in latest_by_type:
        ram_data = json.loads(latest_by_type["ram"])
        ram_current = float(ram_data.get("percent", 0.0))
        if ram_current > ram_threshold:
            conditions.append(f"RAM high: {ram_current:.1f}% > {ram_threshold:.1f}% ({now_iso})")

    if "disk" in latest_by_type:
        disk_data = json.loads(latest_by_type["disk"])
        partitions = disk_data.get("partitions", [])
        if isinstance(partitions, list):
            for part in partitions:
                if not isinstance(part, dict):
                    continue
                current = float(part.get("percent", 0.0))
                mount = str(part.get("mountpoint", "unknown"))
                if current > disk_threshold:
                    conditions.append(
                        f"Disk high on {mount}: {current:.1f}% > {disk_threshold:.1f}% ({now_iso})"
                    )
    if "network" in latest_by_type:
        network_data = json.loads(latest_by_type["network"])
        sent_current = float(network_data.get("bytes_sent", 0.0))
        recv_current = float(network_data.get("bytes_recv", 0.0))
        if network_sent_threshold is not None and sent_current > network_sent_threshold:
            conditions.append(
                f"Network sent high: {int(sent_current)} B > {int(network_sent_threshold)} B ({now_iso})"
            )
        if network_recv_threshold is not None and recv_current > network_recv_threshold:
            conditions.append(
                f"Network recv high: {int(recv_current)} B > {int(network_recv_threshold)} B ({now_iso})"
            )
    if "gpu" in latest_by_type:
        gpu_data = json.loads(latest_by_type["gpu"])
        gpu_utilization = float(
            gpu_data.get("peak_utilization_percent", gpu_data.get("utilization_percent", 0.0))
        )
        gpu_temperature = float(gpu_data.get("temperature_c", 0.0))
        if gpu_utilization > gpu_utilization_threshold:
            conditions.append(
                "GPU utilization high: "
                f"{gpu_utilization:.1f}% > {gpu_utilization_threshold:.1f}% ({now_iso})"
            )
        if gpu_temperature > gpu_temperature_threshold:
            conditions.append(
                "GPU temperature high: "
                f"{gpu_temperature:.1f}°C > {gpu_temperature_threshold:.1f}°C ({now_iso})"
            )
    return conditions
