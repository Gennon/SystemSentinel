# Chat Commands Guide

This guide documents command behavior independently of adapter setup.
For Discord and other adapter configuration, see [chat-adapters.md](chat-adapters.md).

---

## Supported commands

| Command | Default access | Description |
|---|---|---|
| `!help` | readonly | Show all available commands |
| `!status` | readonly | CPU, RAM, disk, uptime, and service health |
| `!ask <question>` | readonly | Ask the configured LLM provider for diagnostics help |
| `!explain` | admin | AI explanation of the most recent alert, including context and next steps |
| `!checkup` | admin | AI-powered full system check with prioritized improvements |
| `!analyze-logs` | admin | AI analysis of recent sentinel audit logs |
| `!config <request>` | admin | Natural-language config update (requires confirmation) |
| `!update` | admin | Run security updates (requires confirmation) |
| `!cleanup` | admin | Run cleanup rules (requires confirmation) |
| `!files` | readonly | List old files from the latest scan |
| `!alerts` | readonly | List active alert conditions |
| `!storage` | readonly | Generate a storage usage report |
| `!snapshots` | readonly | List recent snapshot/rollback points |
| `!anomalies` | readonly | List recent login anomalies |
| `!firewall` | readonly | Show effective firewall rules and drift status |
| `!hardening` | readonly | Show latest hardening audit summary |
| `!2fa` | readonly | Show latest 2FA audit status |
| `!vulnscan` | readonly | Show latest vulnerability scan summary/report |
| `!audit [--count N]` | readonly | List recent audit log entries |
| `!graph <metric> <period>` | readonly | Historical metric graph (24h/7d/30d/90d) |
| `!connections classify` | readonly | Show latest connection intent classifications |
| `!integrity` | readonly | Show monitored file integrity status |
| `!integrity update <path>` | admin | Update file integrity baseline for a legitimate change |
| `!mute <duration>` | admin | Temporarily suppress non-critical alerts |
| `!unmute` | admin | Cancel active mute window |

---

## Access control notes

- Default command access is determined by `chat/access_control.py` (`readonly_commands`).
- You can override readonly command permissions per adapter via `chat_adapters.<adapter>.readonly_commands` in `config.yaml`.
- User-level authorization is controlled by `chat_adapters.<adapter>.allowed_users`.

---

## Image renderer for `!graph`

By default `!graph` returns an ASCII chart.  
For PNG output, install graph extras as the service user:

```bash
sudo -u sentinel .venv/bin/pip install 'system-sentinel[graphs]'
```

Then set `charts.renderer: image` in `config.yaml` and restart the daemon.
