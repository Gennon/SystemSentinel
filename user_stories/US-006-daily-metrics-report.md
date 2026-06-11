# US-006 — Daily resource usage metrics aggregation

**Release:** 1 — Core / MVP
**Area:** Monitoring & Metrics

## Description
As a user I want a daily summary of resource usage trends so I can spot gradual degradation.

## Scope note
This story covers **data aggregation only** — computing 24-hour statistics from the metrics database and making them available as a structured payload. The payload is consumed by the daily digest (see [US-010](US-010-daily-digest.md)), which assembles it together with other data sources into the chat message that is actually sent. US-006 does **not** send any chat message on its own.

## Acceptance Criteria
- [ ] `MetricsRepository` exposes a method that returns 24-hour aggregates (average, peak, minimum) for CPU, RAM, disk, and network per configured collection interval
- [ ] The aggregates include a top-5 list of processes by average CPU and RAM consumption over the window
- [ ] If any metric exceeded its alert threshold during the window, the aggregate result flags this
- [ ] If no metrics were collected for part of the window (daemon was down), the gap is represented explicitly (not silently zeroed)
- [ ] The aggregation is queryable for any arbitrary 24-hour window, not just the current day
