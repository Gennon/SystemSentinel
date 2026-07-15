# US-033 — Policy-based model routing for LLM explanations

**Release:** 3 — Observability & Polish
**Area:** AI / LLM Assistant

## Description
As a user I want policy-based model routing for LLM explanations so I can balance speed, cost, and quality automatically.

## Acceptance Criteria
- [ ] Routing rules are configurable in `config.yaml` based on command/event type and severity
- [ ] The router can target different models (and optionally providers) per rule
- [ ] A default fallback model is always configured and used when no rule matches
- [ ] The `!status` command output includes the active default provider/model
- [ ] Routing decisions are written to the audit log with matched rule metadata
