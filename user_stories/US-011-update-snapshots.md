# US-011 — Pre/post-update snapshots and rollback

**Release:** 2 — Hardening & Intelligence
**Area:** System Maintenance

## Description
As a user I want automatic pre/post-update snapshots or rollback points so I can recover if an update breaks something.

## Acceptance Criteria
- [ ] The snapshot backend is configurable in `config.yaml`; if set to `auto` (default) the daemon probes for available tools and uses the first found
- [ ] If a supported snapshot mechanism is available, the daemon creates a snapshot before applying updates
- [ ] A post-update snapshot is created after a successful update run
- [ ] If snapshot creation fails, the update is skipped and a warning is sent via chat
- [ ] The `!snapshots` chat command lists recent snapshots with their timestamps and labels
- [ ] If no snapshot tool is available, the daemon logs a warning on startup and skips this step gracefully
- [ ] Snapshot creation and deletion are recorded in the audit log
