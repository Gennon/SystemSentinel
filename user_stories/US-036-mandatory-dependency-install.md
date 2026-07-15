# US-036 — Mandatory dependency installation

**Release:** 1 — Core / MVP
**Area:** System Maintenance
**Status:** Done

## Description
As a user I want all mandatory dependencies installed automatically during setup so the daemon works out of the box without me having to know what to install.

## Acceptance Criteria
- [x] Setup detects the system package manager (`apt`, `dnf`, or `pacman`) and uses it to install missing system packages
- [x] The following are installed automatically if not already present:
  - Required Python packages (into a virtualenv)
  - `iproute2` (provides `ss` for network monitoring)
  - `sqlite3`
  - `curl`
- [x] Each package installation is shown with a progress indicator and a ✓ / ✗ result
- [x] Already-installed packages are skipped with a ✓ without reinstalling
- [x] If any mandatory installation fails, the step reports the error and the setup wizard halts (per US-035)
- [x] The OS and architecture are validated first (supported: Linux x86_64 / arm64); an unsupported platform exits with a clear message
