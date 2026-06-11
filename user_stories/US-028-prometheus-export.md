# US-028 — Prometheus-compatible metrics export

**Release:** 3 — Observability & Polish
**Area:** Monitoring & Metrics

## Description
As a user I want a Prometheus-compatible metrics export so I can plug SystemSentinel into an existing Grafana setup.

## Acceptance Criteria
- [ ] The daemon exposes a `/metrics` HTTP endpoint in Prometheus text exposition format
- [ ] The endpoint is served on a configurable port (default: 9100)
- [ ] The following metrics are exported: CPU usage, RAM usage, disk usage per volume, network I/O, GPU metrics (if available), login failure count, active alert count
- [ ] The endpoint can be optionally secured with a bearer token configured in `config.yaml`
- [ ] The Prometheus exporter can be enabled or disabled independently of the rest of the daemon
- [ ] The endpoint responds within 500ms under normal system load
