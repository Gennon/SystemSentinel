# US-020 — chat commands

**Release:** 2 — Hardening & Intelligence
**Area:** Communication & Alerts
**Status:** Done

## Description
As a user I want to send chat commands like `!status`, `!update`, and `!cleanup` to trigger actions remotely so I can manage the system from my phone.

## Acceptance Criteria
- [x] The chat bot listens for commands prefixed with `!` (configurable) in the configured channel
- [x] The following commands are supported in Release 2:
  - `!status` — current CPU, RAM, disk, uptime, and service health
  - `!update` — triggers an immediate security update run
  - `!cleanup` — triggers an immediate file cleanup run (using configured rules)
  - `!files` — lists old files (see US-007)
  - `!alerts` — lists currently active alert conditions
  - `!storage` — triggers storage report (see US-019)
  - `!anomalies` — lists recent login anomalies (see US-015)
  - `!firewall` — shows firewall status (see US-014)
  - `!hardening` — shows hardening audit results (see US-013)
  - `!help` — lists all available commands with a brief description
- [x] Commands that trigger actions (update, cleanup) require confirmation via a bot reply reaction (e.g. user reacts with ✅) before executing
- [x] Access control is enforced per US-034; unauthorised users are rejected before any command is processed
- [x] All commands triggered via chat are recorded in the audit log with the chat username
