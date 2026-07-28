# US-047 — AI analyzes sentinel logs and reports improvement opportunities

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant

## Description
As an admin I want the AI to analyze the latest sentinel logs and report on improvements we can make to SystemSentinel itself when it has errors or warnings, so the sentinel continuously improves its own reliability.

## Acceptance Criteria
- [ ] Admin can trigger log analysis via chat command (e.g. `!analyze-logs`)
- [ ] The AI reads the sentinel audit and application logs covering a configurable look-back window (default: last 7 days)
- [ ] AI identifies recurring errors, warnings, and anomalous patterns in sentinel's own operation
- [ ] AI generates a structured report with findings and concrete improvement suggestions (config changes, tool fixes, threshold adjustments)
- [ ] The report is delivered via chat and written to the audit log
- [ ] Log analysis can also run on a configurable schedule (e.g. weekly)
- [ ] Only users with admin role can trigger on-demand log analysis
- [ ] Sensitive log content (passwords, keys) is redacted before being sent to the LLM
