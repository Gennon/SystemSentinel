# US-049 — AI suggests improved alert thresholds based on historical metrics

**Release:** 4 — AI-Powered Operations
**Area:** AI / LLM Assistant

## Description
As a user I want the AI to analyze historical metric data and recommend more accurate alert thresholds so my alerts reflect real usage patterns rather than generic defaults.

## Acceptance Criteria
- [ ] AI analyzes stored metric history (CPU, RAM, disk, network, GPU if present) over a configurable look-back period (default: 30 days)
- [ ] AI generates threshold recommendations per metric with a brief rationale (e.g. "your p95 CPU is 72%, current threshold of 85% may be too loose")
- [ ] Recommendations are delivered via chat and written to the audit log
- [ ] Admin can accept a recommendation via a chat reply and the AI applies the config change (following the US-044 confirmation flow)
- [ ] Analysis can be triggered on demand (`!tune-thresholds`) or on a configurable schedule (default: monthly)
- [ ] Only users with admin role can trigger on-demand analysis or accept recommendations
