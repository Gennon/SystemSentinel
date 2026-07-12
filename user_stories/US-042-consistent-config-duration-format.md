# US-042 — Consistent config duration format

**Release:** 1 — Core / MVP
**Area:** System Maintenance

## Description
As a user I want all duration-based config values to use a consistent `HH:MM:SS` format so configuration is predictable and easier to read.

## Acceptance Criteria
- [x] Duration config keys use suffix-free names (for example `scan_interval`, `collection_interval`, `check_interval`)
- [x] Duration config values use `HH:MM:SS` format
