# US-018 — Alerts for unexpected directory changes

**Release:** 2 — Hardening & Intelligence
**Area:** File Management
**Status:** Done

## Description
As a user I want alerts when monitored directories change unexpectedly so I know about unauthorized file modifications.

## Acceptance Criteria
- [x] One or more directories to watch for changes can be configured in `config.yaml`
- [x] The daemon uses filesystem events (inotify) to detect: file creation, deletion, modification, and rename in real time
- [x] An alert is sent via chat within 30 seconds of the change with: file path, change type, timestamp, and process owner (if determinable)
- [x] A whitelist of expected change patterns (glob or regex) can be configured per directory to suppress noise (e.g. log rotation)
- [x] Alert cooldown per file path can be configured to prevent storms during bulk operations (default: 5 minutes)
- [x] All detected changes are stored in SQLite for historical review
