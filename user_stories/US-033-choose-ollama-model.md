# US-033 — Policy-based model routing for LLM explanations

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant
**Status:** Done

## Description
As a user I want policy-based model routing for LLM explanations so I can balance speed, cost, and quality automatically.

## Acceptance Criteria
- [x] Routing rules are configurable in `config.yaml` based on command/event type and severity
- [x] The router can target different models (and optionally providers) per rule
- [x] A default fallback model is always configured and used when no rule matches
- [x] The `!status` command output includes the active default provider/model
- [x] Routing decisions are written to the audit log with matched rule metadata
