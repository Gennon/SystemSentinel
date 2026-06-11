# US-004 — Alert on unknown IP connecting to open port

**Release:** 1 — Core / MVP
**Area:** Security & Hardening

## Description
As a user I want an alert when a new unknown IP connects to an open port so I am aware of unexpected network access.

## Scope note
Monitoring is limited to **inbound connections on listening ports** (e.g. SSH, HTTP). Outbound connections are not monitored in this story — the noise-to-signal ratio would be unacceptable for a general-purpose daemon. Anomalous outbound traffic is a future concern.

## Acceptance Criteria
- [ ] The daemon polls active inbound connections on listening ports using `ss -tnp` at a configurable interval (default: 60 seconds)
- [ ] A whitelist of trusted IPs and CIDR ranges can be defined in `config.yaml`; connections from whitelisted IPs are silently ignored
- [ ] When a new inbound connection from an IP not on the whitelist is detected, a chat notification is sent with: source IP, destination port, protocol, and timestamp
- [ ] Each new unknown IP per port is stored in the database; repeat connections from the same IP to the same port do not re-alert within a configurable cooldown period (default: 1 hour)
- [ ] If no whitelist is configured, all IPs are considered unknown and will alert — a startup warning is logged to prompt the user to configure one
