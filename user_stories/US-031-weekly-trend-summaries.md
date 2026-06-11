# US-031 — Weekly trend summaries to chat

**Release:** 3 — Observability & Polish
**Area:** Communication & Alerts

## Description
As a user I want weekly trend summaries (storage growth, login patterns) sent via chat so I can spot slow-moving problems.

## Acceptance Criteria
- [ ] A weekly summary is sent via chat on a configurable day and time (default: Monday 08:00)
- [ ] The weekly report includes:
  - Storage usage trend: change in used disk space per volume over the week
  - Login summary: total successful and failed logins, unique IPs, anomalies detected
  - Resource usage averages compared to the previous week (CPU, RAM, disk)
  - Update history: packages updated during the week
  - File cleanup summary: total files deleted and space reclaimed
  - Security posture: hardening audit result and vulnerability scan delta (if run this week)
- [ ] Trends are expressed as deltas with direction (e.g. "+4.2 GB disk used, +12% vs last week")
- [ ] The weekly report is sent as a multi-section chat message
