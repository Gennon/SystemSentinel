# US-011 — Pre/post-update snapshots and rollback

**Release:** 2 — Hardening & Intelligence
**Area:** System Maintenance
**Status:** Done

## Description
As a user I want automatic pre/post-update snapshots or rollback points so I can recover if an update breaks something.

## Acceptance Criteria
- [x] The snapshot backend is configurable in `config.yaml`; if set to `auto` (default) the daemon probes for available tools and uses the first found
- [x] If a supported snapshot mechanism is available, the daemon creates a snapshot before applying updates
- [x] A post-update snapshot is created after a successful update run
- [x] If snapshot creation fails, the update is skipped and a warning is sent via chat
- [x] The `!snapshots` chat command lists recent snapshots with their timestamps and labels
- [x] If no snapshot tool is available, the daemon logs a warning on startup and skips this step gracefully
- [x] Snapshot creation and deletion are recorded in the audit log
