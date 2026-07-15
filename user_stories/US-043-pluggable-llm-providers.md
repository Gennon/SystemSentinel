# US-043 — Pluggable LLM providers

**Release:** 2 — Hardening & Intelligence
**Area:** AI / LLM Assistant
**Status:** Done

## Description
As a user I want LLM providers to be pluggable and selectable in config so I can switch between Ollama, OpenAI, Anthropic (Claude), and Mistral without core code changes.

## Acceptance Criteria
- [x] LLM providers are discovered via Python entry points (`sentinel.llm_providers`), matching the plugin model used for chat adapters
- [x] The daemon supports selecting the active provider in `config.yaml` (`llm.provider`)
- [x] Provider-specific settings live under `llm_providers.<provider>` and can be enabled/disabled independently
- [x] Built-in providers include Ollama, OpenAI, Anthropic (Claude), and Mistral
- [x] The chat `!ask` command routes requests through the active provider and returns a provider/model-tagged response
- [x] If the active provider is unavailable, the chat response reports the failure explicitly
