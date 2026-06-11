# US-003 — Failed SSH login attempts logged

**Release:** 1 — Core / MVP
**Area:** Security & Hardening

## Description
As a user I want failed SSH login attempts logged with IP address, timestamp, and username so I can see who is trying to get in.

## Acceptance Criteria
- [ ] The daemon monitors the system auth log (e.g. `/var/log/auth.log` or `journald`) for failed SSH events
- [ ] Each failed attempt is stored in the local SQLite database with: IP address, username, timestamp, and SSH port
- [ ] After a configurable number of failed attempts from the same IP within a time window (default: 5 in 10 minutes), a chat notification is sent
- [ ] The alert includes the IP, number of attempts, and the usernames tried
- [ ] A summary of unique attacking IPs is included in the daily digest report
- [ ] The threshold values (attempt count and time window) are the single source of truth reused by the anomaly detection in [US-015](US-015-login-anomaly-detection.md)
