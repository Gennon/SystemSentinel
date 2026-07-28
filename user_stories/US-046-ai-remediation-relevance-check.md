# US-046 — AI checks if remediation suggestions are still relevant before sending

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant
**Status:** Done

## Description
As a user I want the AI to determine whether remediation suggestions are still relevant before sending them, based on current system state, so I only receive alerts about issues that have not yet been addressed.

## Acceptance Criteria
- [x] Before sending a remediation suggestion triggered by an alert, the AI queries the current system state to verify the issue still exists
- [x] If the suggested remediation has already been applied (e.g. the package is installed, the threshold is within range), the suggestion is suppressed and the suppression is logged
- [x] If the issue persists, the suggestion is sent as normal
- [x] Suppressed suggestions are recorded in the audit log with the reason (e.g. "already resolved")
- [x] The relevance check is configurable and can be disabled in `config.yaml` under `llm.remediation.relevance_check`
- [x] The AI reports a brief explanation when a suggestion is suppressed (visible in audit log)
