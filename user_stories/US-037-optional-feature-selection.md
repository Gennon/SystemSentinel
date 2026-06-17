# US-037 — Optional feature selection during setup

**Release:** 1 — Core / MVP
**Area:** System Maintenance

## Description
As a user I want to choose which optional features to enable during setup, with a clear explanation of each, so I only install what I need.

## Acceptance Criteria
- [x] After mandatory installs, the wizard presents a menu of optional features with a one-line description each:
  - **GPU monitoring** — metric collection for NVIDIA/AMD GPUs (auto-suggested if GPU hardware is detected)
  - **System hardening** — CIS benchmark checks and SSH hardening (US-013)
  - **Snapshot / rollback** — pre/post-update snapshots via `snapper` or `timeshift` (US-011)
  - **Vulnerability scanning** — periodic security audits via `lynis` (US-026)
  - **Metrics export** — Prometheus-compatible `/metrics` endpoint (US-028)
- [x] Each feature shows whether its required tool is already installed
- [x] The user selects features via a numbered toggle menu; the default is none selected
- [x] Selected features are installed and enabled in `config.yaml` automatically
- [x] Skipped features can be enabled at any time by re-running `sentinel setup`
- [x] In `--unattended` mode, no optional features are installed unless explicitly passed as flags (e.g. `--enable gpu,lynis`)
