# US-045 — AI-powered full system check with improvement suggestions

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant

## Description
As a user I want the AI to perform a full system check using all sentinel tools and suggest how to improve the system so I get a comprehensive, actionable health report.

## Acceptance Criteria
- [ ] User can trigger a full system check via chat command (e.g. `!checkup`)
- [ ] The AI orchestrates all available sentinel tools (metrics, security audit, file integrity, service health, vulnerability scan, etc.)
- [ ] AI synthesizes results from all tools into a single prioritized report with concrete improvement suggestions
- [ ] The report is delivered via chat and optionally written to the audit log
- [ ] Each suggestion includes a severity level (info / warning / critical) and a recommended action
- [ ] The check can also run on a configurable schedule (e.g. weekly) without manual triggering
- [ ] The command is only available to users with appropriate permissions
