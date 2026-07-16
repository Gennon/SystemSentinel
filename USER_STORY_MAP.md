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
- [x] As a user I want a single setup command that launches a friendly wizard so I can go from a fresh Linux machine to a running daemon without prior knowledge. **(US-035)**
  - Acceptance criteria:
    - `sentinel setup` runs a step-by-step wizard (platform check, dependencies, user creation, config, service install)
    - The wizard grants the `sentinel` system user execute access to the install directory so the service can start even when installed under `~/.local/`
    - `sentinel run` starts the daemon, wires all components (scheduler, monitors, chat adapters, alert handler), and exits cleanly on SIGINT/SIGTERM
    - The systemd service starts successfully after setup with no permission errors
- [x] As a user I want all mandatory dependencies installed automatically during setup so the daemon works out of the box. **(US-036)**
- [x] As a user I want to choose which optional features to enable during setup so I only install what I need. **(US-037)**
- [x] As a user I want the setup wizard to walk me through the minimum required configuration so I don't have to manually edit a config file to get started. **(US-038)**
- [x] As a user I want all duration-based config values to use a consistent `HH:MM:SS` format so configuration is predictable and easier to read. **(US-042)**
- [x] As a user I want the system to auto-apply security patches on a configurable schedule so the machine stays up to date without manual intervention. **(US-001)**
- [x] As a user I want to define a list of required packages that are always installed so the system self-heals if software goes missing. **(US-002)**
- [x] As a user I want the daemon to self-update from the configured update source, notify chat when update starts, and then restart itself so deployed instances stay current automatically. **(US-040)**

### Security & Hardening
- [x] As a user I want failed SSH login attempts logged with IP address, timestamp, and username so I can see who is trying to get in. **(US-003)**
- [x] As a user I want an alert when a new unknown IP connects to an open port so I am aware of unexpected network access. **(US-004)**

### Monitoring & Metrics
- [x] As a user I want CPU, RAM, disk, and network usage metrics collected at a configurable interval so I have a continuous picture of system health. **(US-005)**
- [x] As a user I want a daily summary report of resource usage trends so I can spot gradual degradation. **(US-006)**

### File Management
- [x] As a user I want to see a list of files older than N days in configured directories so I can decide what to clean up. **(US-007)**

### Communication & Alerts
- [x] As a user I want chat notifications for critical events (high CPU, failed logins, disk full) so I am notified immediately. **(US-009)**
- [x] As a user I want a daily digest report sent via chat each morning so I start the day with a system overview. **(US-010)**
- [x] As a user I want a startup chat notification when the service comes online so I know monitoring is active. **(US-041)**

> **Note:** Release 1 chat integration is **outbound only** — SystemSentinel posts alerts and digests to chat. Two-way commands (inbound messages triggering actions) are a Release 2 feature.

---

## Release 2 — Hardening & Intelligence

### System Maintenance
- [x] As a user I want automatic pre/post-update snapshots or rollback points so I can recover if an update breaks something. **(US-011)**
- [x] As a user I want service health checks and auto-restart on failure so critical services stay running. **(US-012)**

### Security & Hardening
- [x] As a user I want the system to auto-apply CIS or custom hardening benchmarks so the machine meets a security baseline. **(US-013)**
- [x] As a user I want firewall rules managed declaratively with a desired-state config so rules are version-controlled and reproducible. **(US-014)**
- [x] As a user I want login anomaly detection (e.g. brute force patterns, off-hours logins) so suspicious behaviour is flagged automatically. **(US-015)**
- [x] As a user I want unknown inbound connection activity classified as likely scanning vs likely access attempt so I can prioritize real threats. **(US-039)**

### Monitoring & Metrics
- [x] As a user I want GPU utilization metrics collected if a GPU is present so I can monitor AI/compute workloads. **(US-016)**
- [x] As a user I want to set alert thresholds per metric (e.g. alert if RAM > 85%) so I only get paged for real problems. **(US-017)**

### File Management
- [ ] As a user I want alerts when monitored directories change unexpectedly so I know about unauthorized file modifications.
- [ ] As a user I want a storage usage report showing top consumers by directory so I know where space is going.

### Communication & Alerts
- [x] As a user I want to send chat commands to trigger actions remotely so I can manage the system from my phone. **(US-020)**
- [x] As a user I want to control who can interact with the chat bot so that only authorised users can trigger actions or receive sensitive system information. **(US-034)**
- [x] As a user I want to configure alert severity levels (info, warning, critical) so I can tune the signal-to-noise ratio. **(US-021)**

### AI / LLM Assistant
- [x] As a user I want LLM providers to be pluggable and selectable in config so I can switch between Ollama, OpenAI, Anthropic (Claude), and Mistral without core code changes. Provider model selection is defined under `llm_providers.<provider>.model`. **(US-043)**
- [x] As a user I want to ask the bot a natural-language question about system health and get an LLM-powered explanation so I can diagnose issues without SSHing in. **(US-022)**
- [x] As a user I want the system to auto-suggest remediation steps when an anomaly is detected so I know what action to take. This is controlled via `llm.remediation`. **(US-023)**

---

## Release 3 — Observability & Polish

### System Maintenance
- [ ] As a user I want a TUI dashboard for system status so I have a single pane of glass view. *(Web dashboard is out of scope for Release 3; may be revisited in a future release.)*
- [ ] As a user I want all automated actions logged to a local audit file with timestamps so I have a full change history.

### Security & Hardening
- [ ] As a user I want periodic vulnerability scanning so I get a security posture report.
- [ ] As a user I want 2FA enforcement audit so the system flags accounts that do not have 2FA enabled.

### Monitoring & Metrics
- [ ] As a user I want a Prometheus-compatible metrics export so I can plug SystemSentinel into an existing Grafana setup.
- [ ] As a user I want configurable retention of historical metric data so I can investigate incidents after the fact.

### File Management
- [ ] As a user I want file integrity monitoring on critical system files so tampering is detected and alerted immediately.
- [ ] As a user I want to optionally auto-delete files based on rules (age, size, pattern) so storage is managed automatically. **(US-008)**

### Communication & Alerts
- [ ] As a user I want weekly trend summaries (storage growth, login patterns) sent via chat so I can spot slow-moving problems.
- [ ] As a user I want configurable quiet hours for non-urgent alerts so I am not woken up by low-priority notifications.

### AI / LLM Assistant
- [ ] As a user I want policy-based model routing (by command type/severity) so I can tune cost, latency, and quality automatically.

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
