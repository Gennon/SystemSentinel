# US-048 — AI correlates multiple alerts into a single root cause

**Status:** Done
**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant

## Description
As a user I want the AI to group related simultaneous alerts and suggest a single root cause so I get focused, actionable insight instead of a flood of separate remediations.

## Acceptance Criteria
- [x] When multiple alerts fire within a configurable time window (default: 5 minutes), the AI evaluates whether they are related
- [x] If a common root cause is identified, a single correlated alert is sent to chat instead of individual messages
- [x] The correlated alert lists all contributing alerts and explains the inferred root cause
- [x] If no correlation is found, alerts are sent individually as normal
- [x] Correlation logic is configurable and can be disabled in `config.yaml` under `llm.alert_correlation.enabled`; the time window is set with `llm.alert_correlation.window` (HH:MM:SS, default `00:05:00`)
- [x] Correlation decisions (grouped or not) are recorded in the audit log
