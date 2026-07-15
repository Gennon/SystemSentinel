# US-002 — Required packages always installed

**Release:** 1 — Core / MVP
**Area:** System Maintenance
**Status:** Done

## Description
As a user I want to define a list of required packages that are always installed so the system self-heals if software goes missing.

## Acceptance Criteria
- [x] A `required_packages` list can be defined in `config.yaml`
- [x] The daemon checks package presence on startup and on a configurable interval (default: every 6 hours)
- [x] Any missing package is automatically installed using the system package manager (apt/dnf/pacman)
- [x] An event is published when a missing package is detected and again when it is successfully reinstalled
- [x] If installation fails, a failure event is published with the package name and error
- [x] Successful auto-installs are recorded in the audit log
