# US-012 — Service health checks and auto-restart

**Release:** 2 — Hardening & Intelligence
**Area:** System Maintenance

## Description
As a user I want service health checks and auto-restart on failure so critical services stay running.

## Acceptance Criteria
- [ ] A list of critical systemd services to monitor can be defined in `config.yaml`
- [ ] The daemon checks service status on a configurable interval (default: 60 seconds)
- [ ] If a monitored service is found in a failed or inactive state, the daemon attempts to restart it via `systemctl restart` (requires a sudoers rule installed by the setup wizard — see ARCHITECTURE.md §14)
- [ ] A chat notification is sent when a service failure is detected, including service name and last journal log lines
- [ ] A follow-up chat message is sent confirming whether the restart succeeded or failed
- [ ] If a service fails to restart after a configurable number of attempts (default: 3), the daemon stops retrying and sends a critical alert
- [ ] All restart attempts are recorded in the audit log
