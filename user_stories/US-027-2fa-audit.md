# US-027 — 2FA enforcement audit

**Release:** 3 — Observability & Polish
**Area:** Security & Hardening
**Status:** Done

## Description
As a user I want a 2FA enforcement audit so the system flags accounts that do not have 2FA enabled.

## Acceptance Criteria
- [x] The daemon audits local user accounts for the presence of a configured 2FA method (e.g. TOTP via Google Authenticator PAM module, or SSH key-only enforcement)
- [x] Accounts without 2FA enabled are listed in the weekly security report and trigger a warning-level chat notification
- [x] A configurable list of accounts exempt from the 2FA requirement can be set in `config.yaml` (e.g. service accounts)
- [x] The `!2fa` chat command shows the current 2FA status for all non-exempt accounts
- [x] If the 2FA audit cannot determine status (e.g. custom auth mechanism), the result is reported as "unknown" rather than "pass"
