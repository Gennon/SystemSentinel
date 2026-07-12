# US-040 — Daemon self-update and restart

**Release:** 1 — Core / MVP
**Area:** System Maintenance

## Description
As a user I want the daemon to self-update from the configured update source and then restart itself so deployed instances stay current automatically.

## Acceptance Criteria
- [x] Self-update can be enabled or disabled via `config.yaml`
- [x] The daemon checks for available updates on a configurable interval
- [x] If an update is available, the daemon applies it automatically
- [x] When a new version is detected and update begins, a chat notification is sent to the configured default channel(s)
- [x] After a successful update, the daemon triggers a controlled restart of the running service
- [x] If an update check or apply step fails, the daemon keeps running and logs a clear error
- [x] The initial implementation supports git-based updates, but keeps config naming/source semantics generic for future update mechanisms
