# US-044 — AI-driven configuration updates via chat

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant
**Status:** Done

## Description
As an admin I want to ask the AI to update configurations as needed so I can manage system settings through natural language commands without manually editing config files.

## Acceptance Criteria
- [x] Admin can send a natural-language config change request via chat (e.g. "set CPU alert threshold to 90%")
- [x] AI interprets the request, identifies the relevant config key(s), and proposes the exact change before applying it
- [x] Admin must confirm the proposed change before it is written to `config.yaml`
- [x] On confirmation, the config is updated and affected components are reloaded or restarted as needed
- [x] The change is recorded in the audit log with the original chat request, the diff applied, and the admin who confirmed it
- [x] If the request is ambiguous or maps to no known config key, the AI asks a clarifying question rather than guessing
- [x] Only users with admin role (per `chat.allowed_users` or equivalent) can trigger config changes
