# US-023 — Auto-suggest remediation steps on anomaly

**Release:** 2 — Hardening & Intelligence
**Area:** AI / LLM Assistant

## Description
As a user I want the system to auto-suggest remediation steps when an anomaly is detected so I know what action to take.

## Acceptance Criteria
- [ ] When a critical alert fires, the daemon optionally queries Ollama for a remediation suggestion
- [ ] This behaviour can be enabled or disabled in `config.yaml` (`llm_remediation: true`)
- [ ] The LLM is given the alert type, metric values, and recent system context to generate a relevant suggestion
- [ ] The suggestion is appended to the chat critical alert as a follow-up message, clearly labelled as an AI suggestion
- [ ] The suggested steps are advisory only; no automatic action is taken based on the LLM response
- [ ] If the LLM suggestion takes more than 15 seconds to generate, it is sent as a separate delayed follow-up message so the initial alert is not delayed
