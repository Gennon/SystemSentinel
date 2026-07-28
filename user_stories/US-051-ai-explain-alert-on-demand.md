# US-051 — AI explains any alert on demand

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant

## Description
As a user I want to reply to any alert in chat with "explain" and get a full AI-powered contextual explanation so I understand what triggered it, why it matters, and what to do — without SSHing in.

## Acceptance Criteria
- [ ] User can reply to any sentinel alert message in chat with `!explain` (or a configured trigger word) to request an explanation
- [ ] The AI explanation includes: what triggered the alert, why it matters, recent history of the same alert, and recommended next steps
- [ ] The AI queries current system state (metrics, logs, service status) to provide context relevant at the time of the request
- [ ] Explanation is delivered as a threaded or follow-up chat message linked to the original alert
- [ ] Explanation requests are recorded in the audit log
- [ ] The feature is available to all permitted chat users (not admin-only)
