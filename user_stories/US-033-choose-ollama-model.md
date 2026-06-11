# US-033 — Choose Ollama model for LLM explanations

**Release:** 3 — Observability & Polish
**Area:** AI / LLM Assistant

## Description
As a user I want to choose which LLM model (via Ollama) is used for explanations so I can balance speed vs quality.

## Acceptance Criteria
- [ ] The Ollama model name is configurable in `config.yaml` (e.g. `llm_model: "llama3.2"`)
- [ ] The `!models` chat command queries the local Ollama instance and lists available models with their sizes
- [ ] The `!model set <name>` chat command switches the active model without restarting the daemon
- [ ] If the configured model is not available in Ollama, the daemon logs a warning on startup and disables LLM features until a valid model is set
- [ ] The currently active model name is shown in the `!status` command output
- [ ] Model changes made via chat are recorded in the audit log
