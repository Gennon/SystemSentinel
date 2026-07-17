# US-028 — Prometheus-compatible metrics export

**Release:** 3 — Observability & Polish
**Area:** Monitoring & Metrics
**Status:** Done

## Description
As a user I want a Prometheus-compatible metrics export so I can plug SystemSentinel into an existing Grafana setup.

## Acceptance Criteria
- [x] The daemon exposes a `/metrics` HTTP endpoint in Prometheus text exposition format
- [x] The endpoint is served on a configurable port (default: 9100)
- [x] The following metrics are exported: CPU usage, RAM usage, disk usage per volume, network I/O, GPU metrics (if available), login failure count, active alert count
- [x] The endpoint can be optionally secured with a bearer token configured in `config.yaml`
- [x] The Prometheus exporter can be enabled or disabled independently of the rest of the daemon
- [x] The endpoint responds within 500ms under normal system load
