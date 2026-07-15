# US-007 — List files older than N days

**Release:** 1 — Core / MVP
**Area:** File Management
**Status:** Done

## Description
As a user I want to see a list of files older than N days in configured directories so I can decide what to clean up.

## Acceptance Criteria
- [x] One or more watched directories and an age threshold (in days) can be configured in `config.yaml`
- [x] The daemon scans configured directories on a configurable schedule (default: daily)
- [x] The scan result lists files with: path, size, last modified date, and age in days
- [x] Results are stored in SQLite for querying
- [x] A summary of files found (count and total size per watched directory) is included in the daily digest (see [US-010](US-010-daily-digest.md))
- [x] In Release 2 the `!files` command will expose this data interactively (see [US-020](US-020-chat-commands.md))
