# US-030 — File integrity monitoring on critical system files

**Release:** 3 — Observability & Polish
**Area:** File Management

## Description
As a user I want file integrity monitoring on critical system files so tampering is detected and alerted immediately.

## Acceptance Criteria
- [ ] A configurable list of files and directories to integrity-monitor can be defined in `config.yaml`
- [ ] Default monitored paths include: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/crontab`
- [ ] On first run, SHA-256 checksums are computed and stored as the baseline in SQLite
- [ ] The daemon verifies checksums on a configurable interval (default: every 10 minutes)
- [ ] Any checksum mismatch triggers an immediate critical chat notification with: file path, expected hash, actual hash, and timestamp
- [ ] The `!integrity` chat command shows the integrity status of all monitored files and when they were last verified
- [ ] The baseline can be updated intentionally via `!integrity update <path>` after confirming a legitimate change (with audit log entry)
