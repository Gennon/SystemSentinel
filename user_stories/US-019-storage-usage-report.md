# US-019 — Storage usage report showing top consumers

**Release:** 2 — Hardening & Intelligence
**Area:** File Management
**Status:** Done

## Description
As a user I want a storage usage report showing top consumers by directory so I know where space is going.

## Acceptance Criteria
- [x] The `!storage` chat command triggers an on-demand storage report
- [x] The report shows disk usage per configured path, broken down by top-10 subdirectories by size
- [x] The report is generated using a non-blocking background scan that does not affect system performance
- [x] A scheduled storage report can be enabled in `config.yaml` (e.g. weekly)
- [x] The report includes: total used, total free, percentage used, and a flag if any volume is above its alert threshold
- [x] The report is sent as a chat message; large reports are split across multiple messages or attached as a file
