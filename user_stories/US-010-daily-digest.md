# US-010 — Daily digest report to chat

**Release:** 1 — Core / MVP
**Area:** Communication & Alerts

## Description
As a user I want a daily digest report sent via chat each morning so I start the day with a system overview.

## Scope note
This story covers **assembling and sending** the single morning chat message. It does not define how each data section is produced — those responsibilities belong to other stories. Specifically, the resource usage section is produced by [US-006](US-006-daily-metrics-report.md) (`MetricsRepository` 24-hour aggregates). US-010 is the only story that sends a scheduled chat message in the morning; there is no separate "metrics report" message.

## Acceptance Criteria
- [ ] `DigestBuilder` assembles a single structured message from the following sections and sends it at a configurable time (default: 08:00 local time):
  - System uptime
  - Update status (last run, packages updated, any pending updates)
  - 24-hour resource usage summary — sourced from US-006 aggregates (avg CPU, peak RAM, disk usage per volume)
  - Count of failed SSH login attempts and unique attacking IPs
  - Count of unknown IPs that connected to open ports
  - Files auto-deleted in the past 24 hours (if any)
  - Any alerts that fired since the last digest
- [ ] The digest is sent as a structured chat message with a title, timestamp, and one field per section
- [ ] If the daemon was offline for part of the 24-hour window, the digest notes the gap
- [ ] The digest send time is configurable in `config.yaml`
- [ ] Only one digest message is sent per day; it is not duplicated even if multiple chat adapters are active
