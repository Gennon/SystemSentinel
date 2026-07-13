# US-021 — Configurable alert severity levels

**Release:** 2 — Hardening & Intelligence
**Area:** Communication & Alerts

## Description
As a user I want to configure alert severity levels (info, warning, critical) so I can tune the signal-to-noise ratio.

## Acceptance Criteria
- [x] Three severity levels are supported: `info`, `warning`, and `critical`
- [x] Each alert type (CPU, RAM, disk, login, network, etc.) can be assigned a severity level in `config.yaml`
- [x] chat notifications are colour-coded by severity: blue (info), yellow (warning), red (critical)
- [x] A minimum severity level for chat notifications can be set (e.g. `notify_min_severity: warning` suppresses info alerts from chat)
- [x] All alert levels including suppressed info-level ones are still written to the audit log
- [x] Severity levels can be overridden per individual rule without changing the global default
