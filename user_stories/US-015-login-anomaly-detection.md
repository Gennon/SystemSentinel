# US-015 — Login anomaly detection

**Release:** 2 — Hardening & Intelligence
**Area:** Security & Hardening
**Status:** Done

## Description
As a user I want login anomaly detection (e.g. brute force patterns, off-hours logins) so suspicious behaviour is flagged automatically.

## Acceptance Criteria
- [x] The daemon detects and alerts on the following anomaly patterns:
  - Brute force: extends the basic detection from [US-003](US-003-ssh-login-logging.md) with pattern analysis; the threshold (count and window) is the same configurable value defined there
  - Off-hours login: a successful login outside a configurable hours window (default: 07:00–22:00)
  - New user login: a successful login from a username that has never logged in before
  - Impossible travel: successful logins from two geographically distant IPs within a short window; requires a locally installed geolocation database — if not present, this check is silently skipped
- [x] Each anomaly type can be individually enabled or disabled in `config.yaml`
- [x] An alert is sent via chat immediately when an anomaly is detected, with full context (user, IP, time, anomaly type)
- [x] Detected anomalies are stored in SQLite for historical review
- [x] The `!anomalies` chat command lists anomalies detected in the last 24 hours
