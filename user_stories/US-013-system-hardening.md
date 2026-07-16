# US-013 — Auto-apply system hardening benchmarks

**Release:** 2 — Hardening & Intelligence
**Area:** Security & Hardening
**Status:** Done

## Description
As a user I want the system to auto-apply CIS or custom hardening benchmarks so the machine meets a security baseline.

## Acceptance Criteria
- [x] A set of hardening rules can be enabled in `config.yaml` (e.g. `tools.hardening.benchmarks.cis_level_1: true`)
- [x] Hardening checks cover at minimum: SSH config (disable root login, disable password auth), kernel parameter hardening (`sysctl`), disabled unnecessary services, and strong password policy
- [x] The daemon runs a hardening audit on startup and on a configurable schedule (default: weekly)
- [x] Audit results are stored and accessible via the `!hardening` chat command showing pass/fail per check
- [x] When `auto_remediate: true` is set, failing checks are automatically fixed and the change is logged in the audit log
- [x] A chat notification is sent for each auto-remediated item
- [x] Hardening changes made manually that conflict with the desired state are re-applied on the next audit run
