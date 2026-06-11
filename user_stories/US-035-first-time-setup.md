# US-035 — First-time setup wizard

**Release:** 1 — Core / MVP
**Area:** System Maintenance

## Description
As a user I want a single command (`sentinel setup`) that launches a friendly interactive wizard so I can go from a fresh Linux machine to a running daemon without prior knowledge.

## Acceptance Criteria
- [ ] Running `sentinel setup` displays a welcome banner and a brief description of what it will do before making any changes
- [ ] The wizard runs through the steps defined in US-036 (dependency install), US-037 (optional features), and US-038 (guided config) in sequence
- [ ] Each step shows a clear progress indicator and a ✓ / ✗ result
- [ ] If any step fails, the wizard stops, explains what went wrong, and suggests a manual fix before exiting with a non-zero code
- [ ] On success, the wizard installs and enables the systemd service, starts the daemon, and confirms it is running
- [ ] A final summary screen lists every completed step and prints "SystemSentinel is running" with a tip for verifying connectivity (e.g. "Send `!status` in your chat channel")
- [ ] Re-running `sentinel setup` on an already-configured system is fully safe and idempotent
- [ ] A `--check` flag runs all checks and reports status without installing or changing anything
- [ ] A `--unattended` flag skips interactive prompts and applies all defaults (for automated provisioning)
