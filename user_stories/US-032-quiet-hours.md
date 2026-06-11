# US-032 — Configurable quiet hours for non-urgent alerts

**Release:** 3 — Observability & Polish
**Area:** Communication & Alerts

## Description
As a user I want configurable quiet hours for non-urgent alerts so I am not woken up by low-priority notifications.

## Acceptance Criteria
- [ ] A quiet hours window (start time, end time) can be configured in `config.yaml` (e.g. `quiet_hours: "22:00-07:00"`)
- [ ] During quiet hours, only `critical` severity alerts are sent via chat immediately
- [ ] `warning` and `info` alerts generated during quiet hours are queued and delivered as a single batch message at the end of quiet hours
- [ ] The `!mute <duration>` chat command temporarily suppresses all non-critical alerts for a specified duration (e.g. `!mute 2h`)
- [ ] The `!unmute` command cancels an active mute
- [ ] Critical alerts (e.g. disk full, file tampering) bypass quiet hours and are always sent immediately
- [ ] The quiet hours status is shown in the `!status` command output
