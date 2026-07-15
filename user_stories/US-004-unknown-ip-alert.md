# US-004 — Alert on unknown IP connecting to open port

**Release:** 1 — Core / MVP
**Area:** Security & Hardening
**Status:** Done

## Description
As a user I want an alert when a new unknown IP connects to an open port so I am aware of unexpected network access.

## Scope note
Monitoring is limited to **inbound connections on listening ports** (e.g. SSH, HTTP). Outbound connections are not monitored in this story — the noise-to-signal ratio would be unacceptable for a general-purpose daemon. Anomalous outbound traffic is a future concern.

## Acceptance Criteria
- [x] The daemon polls active inbound connections on listening ports using `ss -tnp` at a configurable interval (default: 60 seconds)
- [x] A whitelist of trusted IPs and CIDR ranges can be defined in `config.yaml`; connections from whitelisted IPs are silently ignored
- [x] Unknown inbound connection observations are recorded with source IP, destination port, protocol, and timestamp so attempts can be aggregated over time
- [x] An immediate alert is sent only when attempts from the same source IP reach a configurable threshold within a configurable time window (for example 3 attempts in 10 minutes)
- [x] Threshold alerts are rate-limited by a configurable cooldown period so repeated alerts from the same source IP are suppressed
- [x] A daily chat digest summarizes unknown connection activity from the last 24 hours, grouped by source IP and destination port with attempt counts
- [x] If no whitelist is configured, all IPs are considered unknown and will alert — a startup warning is logged to prompt the user to configure one
