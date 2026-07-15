# US-034 — Chat allowed users list

**Release:** 2 — Hardening & Intelligence
**Area:** Communication & Alerts
**Status:** Done

## Description
As a user I want to control who can interact with the chat bot so that only authorised users can trigger actions or receive sensitive system information.

## Acceptance Criteria
- [x] An `allowed_users` list can be defined in `config.yaml` containing user identifiers for the configured chat provider (e.g. Discord user IDs, Slack member IDs)
- [x] Any message or command sent by a user not on the allowed list is silently ignored or responded to with a generic "not authorised" reply (configurable)
- [x] The `allowed_users` list supports at least one admin role with full command access and one read-only role limited to status/query commands
- [x] If the `allowed_users` list is empty or missing, the bot refuses all commands and logs a startup warning
- [x] Changes to the allowed users list in `config.yaml` take effect on the next config reload without restarting the daemon
- [x] All rejected command attempts are logged to the audit log with the requester's user identifier, the attempted command, and the timestamp
