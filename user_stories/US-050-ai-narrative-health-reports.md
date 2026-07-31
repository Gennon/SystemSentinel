# US-050 — AI-generated narrative health reports

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant
**Status:** Done

## Description
As a user I want periodic AI-written narrative health summaries so I understand the system's health trajectory in plain English rather than just raw numbers.

## Acceptance Criteria
- [x] On a configurable schedule (default: weekly), the AI generates a narrative health report in addition to the standard digest
- [x] The report interprets trends rather than just listing values (e.g. "disk growth has accelerated 3× this week, likely due to log rotation being disabled")
- [x] The narrative covers: resource trends, security posture changes, service stability, notable events since the last report
- [x] Report is delivered via chat and written to the audit log
- [x] Report generation can also be triggered on demand via `!health-story`
- [x] Report schedule and look-back window are configurable under `llm.narrative_report`
