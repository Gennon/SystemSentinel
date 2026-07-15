from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
import re
import shutil
import socket
import subprocess
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_from_config
from system_sentinel.monitors.base import BaseMonitor

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext
    from system_sentinel.db.metrics_repository import MetricsRepository


_NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")


def _extract_first_number(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    match = _NUMBER_RE.search(value)
    if match is None:
        return None
    return float(match.group(0))


class GpuMonitor(BaseMonitor):
    """Collects GPU metrics for NVIDIA/AMD devices (US-016)."""

    name = "gpu"

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        metrics_repo: MetricsRepository | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._metrics_repo = metrics_repo
        self._backend: str | None = None
        self._detection_done = False
        self._last_alert_at: datetime | None = None

    async def _get_metrics_repo(self) -> MetricsRepository:
        if self._metrics_repo is not None:
            return self._metrics_repo
        from system_sentinel.db.connection import DatabaseConnection
        from system_sentinel.db.metrics_repository import MetricsRepository as _Repo

        data_dir: str = self.config.get("data_dir", "/var/lib/sentinel")
        db = DatabaseConnection(f"{data_dir}/sentinel.db")
        await db.connect()
        repo = _Repo(db)
        self._metrics_repo = repo
        return repo

    async def collect(self) -> None:
        backend = await self._detect_backend_once()
        if backend is None:
            return

        try:
            data = await asyncio.to_thread(self._sample, backend)
        except Exception:
            self.logger.exception("Failed to collect GPU metrics")
            return
        if data is None:
            return

        await self._maybe_emit_alert(data)

        try:
            repo = await self._get_metrics_repo()
            await repo.insert("gpu", data)
        except Exception:
            self.logger.exception("Failed to persist GPU metrics")

    async def _detect_backend_once(self) -> str | None:
        if self._detection_done:
            return self._backend
        backend = await asyncio.to_thread(self._detect_backend)
        self._backend = backend
        self._detection_done = True
        if backend is None:
            self.logger.info(
                "GPU metrics disabled: no supported GPU detected or required tool missing "
                "(nvidia-smi/rocm-smi)."
            )
        else:
            self.logger.info("GPU metrics enabled with backend=%s.", backend)
        return self._backend

    def _detect_backend(self) -> str | None:
        nvidia_path = shutil.which("nvidia-smi")
        if nvidia_path is not None and self._nvidia_gpu_present(nvidia_path):
            return "nvidia"

        amd_path = shutil.which("rocm-smi")
        if amd_path is not None and self._amd_gpu_present(amd_path):
            return "amd"

        return None

    def _nvidia_gpu_present(self, binary_path: str) -> bool:
        result = subprocess.run(
            [binary_path, "--query-gpu=index", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return False
        return any(line.strip() for line in result.stdout.splitlines())

    def _amd_gpu_present(self, binary_path: str) -> bool:
        result = subprocess.run(
            [binary_path, "--showid", "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return False
        parsed = self._parse_rocm_json(result.stdout)
        return bool(parsed)

    def _sample(self, backend: str) -> dict[str, Any] | None:
        if backend == "nvidia":
            return self._sample_nvidia()
        if backend == "amd":
            return self._sample_amd()
        return None

    def _sample_nvidia(self) -> dict[str, Any] | None:
        binary_path = shutil.which("nvidia-smi")
        if binary_path is None:
            return None
        result = subprocess.run(
            [
                binary_path,
                "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"nvidia-smi exited {result.returncode}: {result.stderr.strip()}")

        gpus: list[dict[str, float]] = []
        for line in result.stdout.splitlines():
            raw = line.strip()
            if not raw:
                continue
            parts = [p.strip() for p in raw.split(",")]
            if len(parts) != 5:
                continue
            gpus.append(
                {
                    "utilization_percent": float(parts[0]),
                    "vram_used_mb": float(parts[1]),
                    "vram_total_mb": float(parts[2]),
                    "temperature_c": float(parts[3]),
                    "power_draw_w": float(parts[4]),
                }
            )

        if not gpus:
            return None
        return self._summarize_gpu_sample(vendor="nvidia", gpus=gpus)

    def _sample_amd(self) -> dict[str, Any] | None:
        binary_path = shutil.which("rocm-smi")
        if binary_path is None:
            return None
        result = subprocess.run(
            [
                binary_path,
                "--showuse",
                "--showmemuse",
                "--showmeminfo",
                "vram",
                "--showtemp",
                "--showpower",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"rocm-smi exited {result.returncode}: {result.stderr.strip()}")

        parsed = self._parse_rocm_json(result.stdout)
        gpus: list[dict[str, float]] = []
        for card_data in parsed.values():
            gpu = self._extract_amd_card_metrics(card_data)
            if gpu is not None:
                gpus.append(gpu)

        if not gpus:
            return None
        return self._summarize_gpu_sample(vendor="amd", gpus=gpus)

    def _parse_rocm_json(self, payload: str) -> dict[str, dict[str, Any]]:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return {}
        if not isinstance(parsed, dict):
            return {}
        cards: dict[str, dict[str, Any]] = {}
        for key, value in parsed.items():
            if not isinstance(key, str) or not key.lower().startswith("card"):
                continue
            if not isinstance(value, dict):
                continue
            cards[key] = value
        return cards

    def _extract_amd_card_metrics(self, card_data: dict[str, Any]) -> dict[str, float] | None:
        util: float | None = None
        temp: float | None = None
        power: float | None = None
        mem_percent: float | None = None
        vram_total_mb: float | None = None
        vram_used_mb: float | None = None

        for key, raw_value in card_data.items():
            lowered = key.lower()
            number = _extract_first_number(raw_value)
            if number is None:
                continue
            if "gpu use" in lowered and "%" in lowered:
                util = number
            elif "temperature" in lowered and "(c" in lowered:
                temp = number
            elif "power" in lowered and "(w" in lowered:
                power = number
            elif "gpu memory use" in lowered and "%" in lowered:
                mem_percent = number
            elif "used vram" in lowered and "(b" in lowered:
                vram_used_mb = number / (1024 * 1024)
            elif "total vram" in lowered and "(b" in lowered:
                vram_total_mb = number / (1024 * 1024)

        if vram_used_mb is None and mem_percent is not None and vram_total_mb is not None:
            vram_used_mb = (mem_percent / 100.0) * vram_total_mb

        if (
            util is None
            or temp is None
            or power is None
            or vram_used_mb is None
            or vram_total_mb is None
        ):
            return None

        return {
            "utilization_percent": util,
            "temperature_c": temp,
            "power_draw_w": power,
            "vram_used_mb": vram_used_mb,
            "vram_total_mb": vram_total_mb,
        }

    def _summarize_gpu_sample(self, *, vendor: str, gpus: list[dict[str, float]]) -> dict[str, Any]:
        util_values = [float(item["utilization_percent"]) for item in gpus]
        temp_values = [float(item["temperature_c"]) for item in gpus]
        power_values = [float(item["power_draw_w"]) for item in gpus]
        vram_used_values = [float(item["vram_used_mb"]) for item in gpus]
        vram_total_values = [float(item["vram_total_mb"]) for item in gpus]

        return {
            "vendor": vendor,
            "device_count": len(gpus),
            "gpus": gpus,
            "utilization_percent": sum(util_values) / len(util_values),
            "peak_utilization_percent": max(util_values),
            "vram_used_mb": sum(vram_used_values),
            "vram_total_mb": sum(vram_total_values),
            "temperature_c": max(temp_values),
            "power_draw_w": sum(power_values),
        }

    async def _maybe_emit_alert(self, data: dict[str, Any]) -> None:
        utilization_threshold = float(self.config.get("alert_threshold_utilization_percent", 95.0))
        temperature_threshold = float(self.config.get("alert_threshold_temperature_c", 85.0))
        cooldown_seconds = parse_duration_from_config(
            self.config,
            key="alert_cooldown",
            default_seconds=30 * 60,
            logger=self.logger,
        )

        current_utilization = float(
            data.get("peak_utilization_percent", data.get("utilization_percent", 0.0))
        )
        current_temperature = float(data.get("temperature_c", 0.0))

        triggered_metrics: list[str] = []
        if current_utilization > utilization_threshold:
            triggered_metrics.append("utilization")
        if current_temperature > temperature_threshold:
            triggered_metrics.append("temperature")
        if not triggered_metrics:
            return

        now = datetime.now(UTC)
        if (
            self._last_alert_at is not None
            and (now - self._last_alert_at).total_seconds() < cooldown_seconds
        ):
            return

        await self.ctx.event_bus.publish(
            "alert.gpu.threshold_exceeded",
            {
                "event_type": "gpu_threshold_exceeded",
                "current_utilization_percent": f"{current_utilization:.1f}%",
                "current_temperature_c": f"{current_temperature:.1f}°C",
                "threshold": (
                    f"util>{utilization_threshold:.1f}% or temp>{temperature_threshold:.1f}°C"
                ),
                "triggered_metrics": triggered_metrics,
                "vendor": str(data.get("vendor", "unknown")),
                "device_count": int(data.get("device_count", 0)),
                "timestamp": now.isoformat(),
                "hostname": socket.gethostname(),
            },
        )
        self._last_alert_at = now
