# US-039 — Classify connection attempts (scan vs access attempt)

**Release:** 2 — Hardening & Intelligence
**Area:** Security & Hardening

## Description
As a user I want unknown inbound connection activity classified as likely background scanning or likely access attempt so I can decide quickly whether to ignore, watch, or block.

## Acceptance Criteria
- [ ] The daemon classifies unknown connection activity into at least three categories: `background_scan`, `suspicious`, and `likely_access_attempt`
- [ ] Classification uses configurable heuristics in `config.yaml`, including at minimum: attempts per IP, distinct destination ports, recurrence over time, and protocol/port sensitivity (for example SSH/RDP)
- [ ] Optional IP enrichment can be enabled to improve confidence (reverse DNS, ASN/organization, and GeoIP); if enrichment data is unavailable, classification still runs and marks those fields as unavailable
- [ ] Each threshold alert for unknown connections includes classification result, confidence, and the reasons that drove the decision
- [ ] The daily connection digest includes a summary by classification category and highlights top IPs per category
- [ ] Classification outcomes are stored in SQLite for historical analysis and trend reporting
- [ ] A chat command (`!connections classify` or equivalent) returns the latest classified connection sources with category, confidence, and recommended action (`ignore`, `watch`, `block`)
