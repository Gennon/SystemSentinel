# US-014 — Declarative firewall rules management

**Release:** 2 — Hardening & Intelligence
**Area:** Security & Hardening
**Status:** Done

## Description
As a user I want firewall rules managed declaratively (UFW/nftables) with a desired-state config so rules are version-controlled and reproducible.

## Acceptance Criteria
- [x] Desired firewall rules are defined in `config.yaml` (e.g. allowed ports, allowed source IPs, default deny policy)
- [x] The daemon supports at least one backend: UFW or nftables (auto-detected based on what is installed); applying rules requires sudoers entries installed by the setup wizard — see ARCHITECTURE.md §14
- [x] On startup and on a configurable schedule (default: every 10 minutes), the daemon reconciles the live firewall state against the desired state
- [x] Any rule that exists in the live firewall but is not in the desired config is flagged as a drift alert in chat
- [x] When `enforce: true` is set, the daemon removes unexpected rules and restores missing ones automatically
- [x] All firewall changes are logged to the audit log with before/after state
- [x] A `!firewall` chat command shows the current effective rules and whether they match the desired config
