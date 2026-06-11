# US-005 — System metrics collected every 60 seconds

**Release:** 1 — Core / MVP
**Area:** Monitoring & Metrics

## Description
As a user I want CPU, RAM, disk, and network usage metrics collected every 60 seconds so I have a continuous picture of system health.

## Acceptance Criteria
- [ ] The daemon collects the following metrics on a configurable interval (default: 60 seconds):
  - CPU usage percentage (overall and per core)
  - RAM usage (total, used, available, percentage)
  - Disk usage per mounted volume (total, used, free, percentage)
  - Network I/O (bytes sent/received since last interval)
- [ ] All metrics are stored in SQLite with a timestamp
- [ ] The collection interval is configurable in `config.yaml`
- [ ] Metric collection failures are logged but do not crash the daemon
- [ ] Data older than a configurable retention period (default: 30 days) is automatically purged
