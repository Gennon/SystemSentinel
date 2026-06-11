# US-001 — Auto-apply security patches

**Release:** 1 — Core / MVP
**Area:** System Maintenance

## Description
As a user I want the system to auto-apply security patches on a configurable schedule so the machine stays up to date without manual intervention.

## Acceptance Criteria
- [ ] A cron-style schedule for updates can be configured in `config.yaml` (e.g. `update_schedule: "02:00"` for 2 AM daily)
- [ ] On schedule, only security-classified updates are applied (not full dist-upgrades)
- [ ] The update run is logged to the audit log with timestamp, list of packages updated, and exit status
- [ ] If an update fails, a chat notification is sent with the package name and error output
- [ ] A dry-run mode can be enabled in config to simulate updates without applying them
- [ ] The daemon does not require a reboot without explicit user approval (reboot is flagged in chat if required)
