# SystemSentinel — User Story Map

## Vision
A Linux system management daemon that autonomously handles updates, security hardening, monitoring, and user communication — surfacing insights and alerts via chat and a local LLM assistant. Install once, stay safe and informed.

## Tech Stack
| Decision | Choice |
|---|---|
| Language | Python |
| Chat integration | Plugin-based (Discord first) — full bot with two-way commands + alerts |
| LLM | Plugin-based providers (Ollama default, plus OpenAI, Anthropic/Claude, Mistral) |
| Packaging | `pip install` + systemd service |
| Config | YAML |
| Metrics storage | SQLite |

---

## Activities & Backbone Tasks

| Activity | System Maintenance | Security & Hardening | Monitoring & Metrics | File Management | Communication & Alerts | AI / LLM Assistant |
|---|---|---|---|---|---|---|
| **Backbone tasks** | Install updates, Install software, Manage services | Audit logins, Monitor network, Harden config, Manage firewall | Collect metrics, Track CPU/RAM/GPU, Alert thresholds | Scan filesystem, Find old files, Clean up files, Monitor changes | Send chat messages, Receive commands, Schedule reports | Query LLM, Get remediation advice, Explain alerts |

---

## Release 1 — Core / MVP

### System Maintenance
- [x] As a user I want a single setup command that launches a friendly wizard so I can go from a fresh Linux machine to a running daemon without prior knowledge. [**(US-035)**](user_stories/US-035-first-time-setup.md)
  - Acceptance criteria:
    - `sentinel setup` runs a step-by-step wizard (platform check, dependencies, user creation, config, service install)
    - The wizard grants the `sentinel` system user execute access to the install directory so the service can start even when installed under `~/.local/`
    - `sentinel run` starts the daemon, wires all components (scheduler, monitors, chat adapters, alert handler), and exits cleanly on SIGINT/SIGTERM
    - The systemd service starts successfully after setup with no permission errors
- [x] As a user I want all mandatory dependencies installed automatically during setup so the daemon works out of the box. [**(US-036)**](user_stories/US-036-mandatory-dependency-install.md)
- [x] As a user I want to choose which optional features to enable during setup so I only install what I need. [**(US-037)**](user_stories/US-037-optional-feature-selection.md)
- [x] As a user I want the setup wizard to walk me through the minimum required configuration so I don't have to manually edit a config file to get started. [**(US-038)**](user_stories/US-038-guided-configuration.md)
- [x] As a user I want all duration-based config values to use a consistent `HH:MM:SS` format so configuration is predictable and easier to read. [**(US-042)**](user_stories/US-042-consistent-config-duration-format.md)
- [x] As a user I want the system to auto-apply security patches on a configurable schedule so the machine stays up to date without manual intervention. [**(US-001)**](user_stories/US-001-auto-security-patches.md)
- [x] As a user I want to define a list of required packages that are always installed so the system self-heals if software goes missing. [**(US-002)**](user_stories/US-002-required-packages.md)
- [x] As a user I want the daemon to self-update from the configured update source, notify chat when update starts, and then restart itself so deployed instances stay current automatically. [**(US-040)**](user_stories/US-040-daemon-self-update-and-restart.md)

### Security & Hardening
- [x] As a user I want failed SSH login attempts logged with IP address, timestamp, and username so I can see who is trying to get in. [**(US-003)**](user_stories/US-003-ssh-login-logging.md)
- [x] As a user I want an alert when a new unknown IP connects to an open port so I am aware of unexpected network access. [**(US-004)**](user_stories/US-004-unknown-ip-alert.md)

### Monitoring & Metrics
- [x] As a user I want CPU, RAM, disk, and network usage metrics collected at a configurable interval so I have a continuous picture of system health. [**(US-005)**](user_stories/US-005-system-metrics-collection.md)
- [x] As a user I want a daily summary report of resource usage trends so I can spot gradual degradation. [**(US-006)**](user_stories/US-006-daily-metrics-report.md)

### File Management
- [x] As a user I want to see a list of files older than N days in configured directories so I can decide what to clean up. [**(US-007)**](user_stories/US-007-list-old-files.md)

### Communication & Alerts
- [x] As a user I want chat notifications for critical events (high CPU, failed logins, disk full) so I am notified immediately. [**(US-009)**](user_stories/US-009-chat-critical-alerts.md)
- [x] As a user I want a daily digest report sent via chat each morning so I start the day with a system overview. [**(US-010)**](user_stories/US-010-daily-digest.md)
- [x] As a user I want a startup chat notification when the service comes online so I know monitoring is active. [**(US-041)**](user_stories/US-041-service-startup-chat-notification.md)

> **Note:** Release 1 chat integration is **outbound only** — SystemSentinel posts alerts and digests to chat. Two-way commands (inbound messages triggering actions) are a Release 2 feature.

---

## Release 2 — Hardening & Intelligence

### System Maintenance
- [x] As a user I want automatic pre/post-update snapshots or rollback points so I can recover if an update breaks something. [**(US-011)**](user_stories/US-011-update-snapshots.md)
- [x] As a user I want service health checks and auto-restart on failure so critical services stay running. [**(US-012)**](user_stories/US-012-service-health-checks.md)

### Security & Hardening
- [x] As a user I want the system to auto-apply CIS or custom hardening benchmarks so the machine meets a security baseline. [**(US-013)**](user_stories/US-013-system-hardening.md)
- [x] As a user I want firewall rules managed declaratively with a desired-state config so rules are version-controlled and reproducible. [**(US-014)**](user_stories/US-014-declarative-firewall.md)
- [x] As a user I want login anomaly detection (e.g. brute force patterns, off-hours logins) so suspicious behaviour is flagged automatically. [**(US-015)**](user_stories/US-015-login-anomaly-detection.md)
- [x] As a user I want unknown inbound connection activity classified as likely scanning vs likely access attempt so I can prioritize real threats. [**(US-039)**](user_stories/US-039-connection-intent-classification.md)

### Monitoring & Metrics
- [x] As a user I want GPU utilization metrics collected if a GPU is present so I can monitor AI/compute workloads. [**(US-016)**](user_stories/US-016-gpu-metrics.md)
- [x] As a user I want to set alert thresholds per metric (e.g. alert if RAM > 85%) so I only get paged for real problems. [**(US-017)**](user_stories/US-017-alert-thresholds.md)

### File Management
- [x] As a user I want alerts when monitored directories change unexpectedly so I know about unauthorized file modifications. [**(US-018)**](user_stories/US-018-directory-change-alerts.md)
- [x] As a user I want a storage usage report showing top consumers by directory so I know where space is going. [**(US-019)**](user_stories/US-019-storage-usage-report.md)

### Communication & Alerts
- [x] As a user I want to send chat commands to trigger actions remotely so I can manage the system from my phone. [**(US-020)**](user_stories/US-020-chat-commands.md)
- [x] As a user I want to control who can interact with the chat bot so that only authorised users can trigger actions or receive sensitive system information. [**(US-034)**](user_stories/US-034-chat-allowed-users.md)
- [x] As a user I want to configure alert severity levels (info, warning, critical) so I can tune the signal-to-noise ratio. [**(US-021)**](user_stories/US-021-alert-severity-levels.md)

### AI / LLM Assistant
- [x] As a user I want LLM providers to be pluggable and selectable in config so I can switch between Ollama, OpenAI, Anthropic (Claude), and Mistral without core code changes. Provider model selection is defined under `llm_providers.<provider>.model`. [**(US-043)**](user_stories/US-043-pluggable-llm-providers.md)
- [x] As a user I want to ask the bot a natural-language question about system health and get an LLM-powered explanation so I can diagnose issues without SSHing in. [**(US-022)**](user_stories/US-022-llm-anomaly-explanation.md)
- [x] As a user I want the system to auto-suggest remediation steps when an anomaly is detected so I know what action to take. This is controlled via `llm.remediation`. [**(US-023)**](user_stories/US-023-llm-auto-remediation.md)

---

## Release 3 — Observability & Polish

### System Maintenance
- [x] As a user I want a TUI dashboard for system status so I have a single pane of glass view. *(Web dashboard is out of scope for Release 3; may be revisited in a future release.)* [**(US-024)**](user_stories/US-024-tui-dashboard.md)
- [x] As a user I want all automated actions logged to a local audit file with timestamps so I have a full change history. [**(US-025)**](user_stories/US-025-audit-log.md)

### Security & Hardening
- [x] As a user I want periodic vulnerability scanning so I get a security posture report. [**(US-026)**](user_stories/US-026-vulnerability-scanning.md)
- [x] As a user I want 2FA enforcement audit so the system flags accounts that do not have 2FA enabled. [**(US-027)**](user_stories/US-027-2fa-audit.md)

### Monitoring & Metrics
- [x] As a user I want a Prometheus-compatible metrics export so I can plug SystemSentinel into an existing Grafana setup. [**(US-028)**](user_stories/US-028-prometheus-export.md)
- [x] As a user I want configurable retention of historical metric data so I can investigate incidents after the fact. [**(US-029)**](user_stories/US-029-historical-metrics.md)

### File Management
- [x] As a user I want file integrity monitoring on critical system files so tampering is detected and alerted immediately. [**(US-030)**](user_stories/US-030-file-integrity-monitoring.md)
- [x] As a user I want to optionally auto-delete files based on rules (age, size, pattern) so storage is managed automatically. [**(US-008)**](user_stories/US-008-auto-delete-files.md)

### Communication & Alerts
- [x] As a user I want weekly trend summaries (storage growth, login patterns) sent via chat so I can spot slow-moving problems. [**(US-031)**](user_stories/US-031-weekly-trend-summaries.md)
- [x] As a user I want configurable quiet hours for non-urgent alerts so I am not woken up by low-priority notifications. [**(US-032)**](user_stories/US-032-quiet-hours.md)

---

## Release 4 — AI-Powered Operations

### AI / LLM Assistant
- [ ] As a user I want policy-based model routing (by command type/severity) so I can tune cost, latency, and quality automatically. [**(US-033)**](user_stories/US-033-choose-ollama-model.md)
- [ ] As an admin I want to ask the AI to update configurations as needed so I can manage system settings through natural language commands without manually editing config files. [**(US-044)**](user_stories/US-044-ai-update-configuration.md)
- [ ] As a user I want the AI to perform a full system check using all sentinel tools and suggest how to improve the system so I get a comprehensive, actionable health report. [**(US-045)**](user_stories/US-045-ai-full-system-check.md)
- [ ] As a user I want the AI to determine whether remediation suggestions are still relevant before sending them, based on current system state, so I only receive alerts about issues that have not yet been addressed. [**(US-046)**](user_stories/US-046-ai-remediation-relevance-check.md)
- [ ] As an admin I want the AI to analyze the latest sentinel logs and report on improvements we can make to SystemSentinel itself when it has errors or warnings, so the sentinel continuously improves its own reliability. [**(US-047)**](user_stories/US-047-ai-log-analysis-for-sentinel-improvements.md)
- [ ] As a user I want the AI to group related simultaneous alerts and suggest a single root cause so I get focused, actionable insight instead of a flood of separate remediations. [**(US-048)**](user_stories/US-048-ai-alert-correlation.md)
- [ ] As a user I want the AI to analyze historical metric data and recommend more accurate alert thresholds so my alerts reflect real usage patterns rather than generic defaults. [**(US-049)**](user_stories/US-049-ai-threshold-tuning.md)
- [ ] As a user I want periodic AI-written narrative health summaries so I understand the system's health trajectory in plain English rather than just raw numbers. [**(US-050)**](user_stories/US-050-ai-narrative-health-reports.md)
- [ ] As a user I want to reply to any alert in chat with `!explain` and get a full AI-powered contextual explanation so I understand what triggered it, why it matters, and what to do without SSHing in. [**(US-051)**](user_stories/US-051-ai-explain-alert-on-demand.md)

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full architecture, coding standards, and developer guides for adding tools, chat integrations, and LLM providers.

```
┌─────────────────────────────────────────┐
│              SystemSentinel             │
│              (systemd daemon)           │
├──────────┬──────────┬───────────────────┤
│  Agent   │ Monitor  │   Notification    │
│  Engine  │ Engine   │   Engine          │
│          │          │                   │
│ • update │ • CPU    │ • chat bot        │
│ • harden │ • RAM    │ • Alert routing   │
│ • install│ • GPU    │ • Digest builder  │
│ • cleanup│ • Disk   │                   │
│          │ • Network│                   │
│          │ • Logins │                   │
│          │ • Files  │                   │
├──────────┴──────────┴───────────────────┤
│        LLM Interface (Ollama)           │
├─────────────────────────────────────────┤
│   config.yaml  │  audit.db (SQLite)     │
└─────────────────────────────────────────┘
```

**Four plugin extension points:**
- **Tools** (`tools/base.py` → `BaseTool`) — units of work run on schedule or via chat command
- **Chat adapters** (`chat/base.py` → `BaseChatAdapter`) — two-way messaging platforms
- **LLM providers** (`llm/base.py` → `BaseLLMProvider`) — language model backends
- **Chart renderers** (`charts/base.py` → `BaseChartRenderer`) — pluggable chart output (text or image)

All four use Python entry points for auto-discovery — adding a plugin requires no changes to core code.
