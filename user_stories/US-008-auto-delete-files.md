# US-008 — Auto-delete files based on rules

**Release:** 3 — Observability & Polish
**Area:** File Management

## Description
As a user I want to optionally auto-delete files based on rules (age, size, pattern) so storage is managed automatically.

## Acceptance Criteria
- [ ] Cleanup rules can be defined in `config.yaml` with the following criteria: directory path, minimum age (days), minimum size (MB), and filename glob pattern
- [ ] Auto-delete is opt-in and disabled by default; it must be explicitly enabled per rule
- [ ] Before deleting, the daemon logs the full file path, size, and matched rule to the audit log
- [ ] A chat notification lists all files deleted in each cleanup run
- [ ] If a file cannot be deleted (e.g. permission denied), a warning alert is sent and the file is skipped
- [ ] A `dry_run: true` option per rule previews what would be deleted without actually removing files
- [ ] Symlinks are never followed during deletion
