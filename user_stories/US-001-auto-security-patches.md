# US-001 — Auto-apply security patches

**Release:** 1 — Core / MVP
**Area:** System Maintenance
**Status:** Done

## Description
As a user I want the system to auto-apply security patches on a configurable schedule so the machine stays up to date without manual intervention.

## Acceptance Criteria
- [x] A cron-style schedule for updates can be configured in `config.yaml` (e.g. `update_schedule: "02:00"` for 2 AM daily)
- [x] On schedule, only security-classified updates are applied (not full dist-upgrades)
- [x] The update run is logged to the audit log with timestamp, list of packages updated, and exit status
- [x] If an update fails, a failure event is published on the event bus (downstream chat notification)
- [x] A dry-run mode can be enabled in config to simulate updates without applying them
- [x] The daemon does not require a reboot without explicit user approval (reboot is flagged via event when `reboot_policy: notify`; suppressed when `reboot_policy: never`)
