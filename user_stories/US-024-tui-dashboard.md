# US-024 — TUI dashboard for system status

**Release:** 3 — Observability & Polish
**Area:** System Maintenance

## Description
As a user I want a TUI or web dashboard for system status so I have a single pane of glass view.

## Acceptance Criteria
- [ ] Running `sentinel dashboard` (or `sentinel-tui`) launches a terminal UI in the current shell session
- [ ] The dashboard shows live-updating panels for: CPU, RAM, disk, network, GPU (if present), active alerts, and recent audit log entries
- [ ] Data is read from the local SQLite database; the dashboard does not require the daemon to be running to display historical data
- [ ] The dashboard refreshes at a configurable interval (default: 5 seconds)
- [ ] Keyboard navigation allows switching between panels and scrolling through historical data
- [ ] The dashboard exits cleanly on `q` or `Ctrl+C` without leaving the terminal in a broken state
