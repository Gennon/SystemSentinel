# US-016 — GPU utilization metrics

**Release:** 2 — Hardening & Intelligence
**Area:** Monitoring & Metrics
**Status:** Done

## Description
As a user I want GPU utilization metrics collected if a GPU is present so I can monitor AI/compute workloads.

## Acceptance Criteria
- [x] The daemon auto-detects whether an NVIDIA or AMD GPU is present on startup
- [x] If a supported GPU is found, the following metrics are collected at the standard interval: GPU utilization (%), VRAM used/total, GPU temperature (°C), power draw (W)
- [x] GPU metrics are stored in SQLite alongside CPU/RAM metrics
- [x] GPU metrics are included in the daily digest report when a GPU is present
- [x] Alert thresholds for GPU utilization and temperature can be configured independently (default: 95% utilization, 85°C)
- [x] If no GPU is detected or the required tool (`nvidia-smi`, `rocm-smi`) is not installed, the daemon skips GPU collection silently and notes this in the startup log
