# US-029 — Historical metric graphs retained 30+ days

**Release:** 3 — Observability & Polish
**Area:** Monitoring & Metrics

## Description
As a user I want historical metric graphs retained for 30+ days so I can investigate incidents after the fact.

## Acceptance Criteria
- [ ] Collected metrics are stored in SQLite with a configurable retention period (default: 90 days)
- [ ] Metrics older than the retention period are automatically purged in a nightly cleanup job
- [ ] The `!graph <metric> <period>` chat command returns a chart (e.g. `!graph cpu 7d`) generated from stored data
- [ ] Supported periods: `24h`, `7d`, `30d`, `90d`
- [ ] Supported metrics for graphing: cpu, ram, disk, network, gpu (if available)
- [ ] The chart renderer is pluggable via `charts.renderer` in `config.yaml`; the default renderer sends a unicode text chart as a chat code block (no extra dependencies); an image renderer (PNG attachment) is available as an opt-in extra
- [ ] If there is insufficient data for the requested period (e.g. daemon was recently installed), the chart shows available data with a note
