# US-017 — Configurable alert thresholds per metric

**Release:** 2 — Hardening & Intelligence
**Area:** Monitoring & Metrics
**Status:** Done

## Description
As a user I want to set alert thresholds per metric (e.g. alert if RAM > 85%) so I only get paged for real problems.

## Acceptance Criteria
- [x] Thresholds for all metrics (CPU, RAM, disk per volume, network, GPU) can be set in `config.yaml`
- [x] Each threshold supports two levels: `warning` and `critical`, sending differently coloured chat notifications
- [x] Thresholds support `>` (above) and `<` (below) operators (e.g. to alert if a service's CPU drops to 0%)
- [x] A sustained-duration requirement can be set per threshold (e.g. "only alert if CPU > 90% for 5 consecutive minutes") to avoid flapping alerts
- [x] When a metric recovers below the threshold, a resolution chat message is sent noting the duration of the breach
- [x] Default thresholds are applied when none are configured, with sensible values documented in the example config
