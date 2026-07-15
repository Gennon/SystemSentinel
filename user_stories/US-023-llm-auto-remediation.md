# US-023 — Auto-suggest remediation steps on anomaly

**Release:** 2 — Hardening & Intelligence
**Area:** AI / LLM Assistant
**Status:** Done

## Description
As a user I want the system to auto-suggest remediation steps when an anomaly is detected so I know what action to take.

## Acceptance Criteria
- [x] When a critical alert fires, the daemon optionally queries the configured active LLM provider for a remediation suggestion
- [x] This behaviour can be enabled or disabled in `config.yaml` (`llm_remediation: true`)
- [x] The LLM is given the alert type, metric values, and recent system context to generate a relevant suggestion
- [x] The suggestion is appended to the chat critical alert as a follow-up message, clearly labelled as an AI suggestion
- [x] The suggested steps are advisory only; no automatic action is taken based on the LLM response
- [x] If the LLM suggestion takes more than 15 seconds to generate, it is sent as a separate delayed follow-up message so the initial alert is not delayed
