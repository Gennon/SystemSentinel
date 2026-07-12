# US-009 — chat notifications for critical events

**Release:** 1 — Core / MVP
**Area:** Communication & Alerts

## Description
As a user I want chat notifications for critical events (high CPU, failed logins, disk full) so I am notified immediately.

## Acceptance Criteria
- [x] A chat bot token and channel ID are configured in `config.yaml`
- [x] Alerts are sent immediately (within one collection interval) when any of the following occur:
  - CPU usage exceeds threshold (default: 90%) for more than 2 consecutive intervals
  - RAM usage exceeds threshold (default: 90%)
  - Any disk volume exceeds threshold (default: 85% used)
  - 5 or more failed SSH logins from the same IP within 10 minutes
- [x] Each alert includes: event type, current value, threshold, timestamp, and hostname
- [x] Alert severity is colour-coded in the chat message (yellow = warning, red = critical)
- [x] Repeat alerts for the same condition are suppressed for a configurable cooldown (default: 30 minutes) to prevent alert fatigue
