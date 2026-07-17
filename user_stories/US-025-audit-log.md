# US-025 — Audit log of all automated actions

**Release:** 3 — Observability & Polish
**Area:** System Maintenance
**Status:** Done

## Description
As a user I want all automated actions logged to a local audit file with timestamps so I have a full change history.

## Scope note
The core `AuditRepository` (SQLite append-only log) is foundational infrastructure present from Release 1 — every story that references "logged to the audit log" depends on it. This story covers the **human-facing layer** added in Release 3: mirroring audit entries to a readable text file and exposing them via the `!audit` chat command.

## Acceptance Criteria
- [x] Every automated action is appended to the audit log with: ISO 8601 timestamp, action type, description, outcome (success/failure), and triggering source (schedule, chat command, alert)
- [x] The audit log is stored in SQLite and also mirrored to a human-readable text file at a configurable path (default: `/var/log/sentinel/audit.log`)
- [x] The `!audit` chat command returns the last N entries (default: 20, configurable via `--count`)
- [x] The audit log is never automatically deleted; a separate retention policy for the text file can be configured
- [x] Log entries are append-only; existing entries cannot be modified by the daemon
- [x] The audit log survives daemon restarts without data loss
