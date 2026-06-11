# US-022 — Ask the bot questions via Ollama

**Release:** 2 — Hardening & Intelligence
**Area:** AI / LLM Assistant

## Description
As a user I want to ask the bot a question (e.g. "why is CPU high?") and get an Ollama-powered explanation so I can diagnose issues without SSHing in.

## Acceptance Criteria
- [ ] The chat bot accepts natural-language questions prefixed with `!ask` (e.g. `!ask why is CPU so high?`)
- [ ] The bot gathers relevant context (current metrics, recent alerts, top processes) and sends a prompt to a local Ollama instance
- [ ] The Ollama model and API endpoint are configurable in `config.yaml`
- [ ] The bot replies with the LLM's response within 30 seconds; if it takes longer, a "thinking..." message is sent first
- [ ] If Ollama is unavailable, the bot replies with an error message explaining the LLM is offline rather than silently failing
- [ ] The LLM response and the context used are stored in the audit log for traceability
- [ ] The `!ask` command only responds to users on the allowed users list
