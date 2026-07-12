# Configuration Reference (`/etc/sentinel/config.yaml`)

This is the authoritative reference for runtime configuration keys in SystemSentinel.

**Maintenance rule:** whenever a config key is added, removed, renamed, or its behavior/default changes, update this file in the same change.

## Duration format

The following keys use duration parsing from `system_sentinel.core.time_config`:

- `HH:MM:SS` (example: `00:05:00`)
- `<days>d HH:MM:SS` (example: `30d 00:00:00`)

## Complete key map

| Key | Type | Default | Used by | Notes |
|---|---|---|---|---|
| `chat_adapters.<adapter>.enabled` | bool | `false` | `ChatRegistry` | Must be `true` to load an adapter. |
| `chat_adapters.discord.token` | string | none | `DiscordAdapter` | Required when `chat_adapters.discord.enabled=true`. |
| `chat_adapters.discord.channel_id` | string/int | none | `DiscordAdapter` | Default destination channel for outgoing messages. |
| `chat_adapters.<adapter>.allowed_users` | list[string \| object] | `[]` | `ChatAccessControl` | Allowed user IDs. String entries are treated as admin. Object entries use `{id, role}` where `role` is `admin` or `readonly`. |
| `chat_adapters.<adapter>.unauthorized_response` | string | `silent` | `ChatAccessControl` | `silent` ignores unauthorized users; `deny_message` sends a generic denial reply. |
| `chat_adapters.<adapter>.unauthorized_message` | string | `Not authorised.` | `ChatAccessControl` | Message used when `unauthorized_response=deny_message`. |
| `chat_adapters.<adapter>.readonly_commands` | list[string] | built-in readonly set | `ChatAccessControl` | Commands allowed for `readonly` users. |
| `monitors.collection_interval` | duration | `00:01:00` | `MonitorRegistry` | Global collection loop interval for all monitors. |
| `monitors.retention` | duration | `30d 00:00:00` | `MonitorRegistry` | Metric retention window (daily purge). |
| `monitors.<monitor>.enabled` | bool | `true` | `MonitorRegistry`/`BaseMonitor` | Per-monitor enable/disable switch. |
| `monitors.cpu.data_dir` | path | `/var/lib/sentinel` | `CpuMonitor` | Used to locate `sentinel.db`. |
| `monitors.cpu.alert_threshold_percent` | number | `90` | `CpuMonitor` | Alert threshold for CPU usage. |
| `monitors.cpu.alert_consecutive_intervals` | int | `2` | `CpuMonitor` | Alert fires after this many consecutive high samples (strictly greater than this value). |
| `monitors.cpu.alert_cooldown` | duration | `00:30:00` | `CpuMonitor` | Minimum time between CPU alerts. |
| `monitors.ram.data_dir` | path | `/var/lib/sentinel` | `RamMonitor` | Used to locate `sentinel.db`. |
| `monitors.ram.alert_threshold_percent` | number | `90` | `RamMonitor` | Alert threshold for RAM usage. |
| `monitors.ram.alert_cooldown` | duration | `00:30:00` | `RamMonitor` | Minimum time between RAM alerts. |
| `monitors.disk.data_dir` | path | `/var/lib/sentinel` | `DiskMonitor` | Used to locate `sentinel.db`. |
| `monitors.disk.alert_threshold_percent` | number | `85` | `DiskMonitor` | Alert threshold for disk usage per mountpoint. |
| `monitors.disk.alert_cooldown` | duration | `00:30:00` | `DiskMonitor` | Minimum time between disk alerts (per mountpoint). |
| `monitors.network.data_dir` | path | `/var/lib/sentinel` | `NetworkMonitor` | Used to locate `sentinel.db`. |
| `monitors.logins.data_dir` | path | `/var/lib/sentinel` | `LoginMonitor` | Used to locate `sentinel.db`. |
| `monitors.logins.failed_login_alert_count` | int | `5` | `LoginMonitor` | Brute-force alert threshold. |
| `monitors.logins.failed_login_window` | duration | `00:10:00` | `LoginMonitor` | Brute-force detection window. |
| `monitors.logins.alert_cooldown` | duration | `00:30:00` | `LoginMonitor` | Minimum time between alerts per source IP. |
| `monitors.connections.data_dir` | path | `/var/lib/sentinel` | `ConnectionMonitor` | Used to locate `sentinel.db`. |
| `monitors.connections.whitelist` | list[string] | `[]` | `ConnectionMonitor` | Entries can be IPs or CIDR ranges. |
| `monitors.connections.repeat_alert_count` | int | `3` | `ConnectionMonitor` | Repeated-attempt alert threshold. |
| `monitors.connections.repeat_alert_window` | duration | `00:10:00` | `ConnectionMonitor` | Window for `repeat_alert_count`. |
| `monitors.connections.cooldown` | duration | `01:00:00` | `ConnectionMonitor` | Alert cooldown per source IP. |
| `monitors.old_files.data_dir` | path | `/var/lib/sentinel` | `OldFilesMonitor` | Used to locate `sentinel.db`. |
| `monitors.old_files.watched_directories` | list[path] | `[]` | `OldFilesMonitor` | Empty disables scanning (with warning). |
| `monitors.old_files.scan_interval` | duration | `24:00:00` | `OldFilesMonitor` | Time between scans. |
| `monitors.old_files.age_threshold` | duration | `30d 00:00:00` | `OldFilesMonitor` | Minimum file age to include in scan results. |
| `monitors.daily_digest.data_dir` | path | `/var/lib/sentinel` | `DailyDigestMonitor` | Used to locate `sentinel.db`. |
| `monitors.daily_digest.send_time_local` | `HH:MM` | `08:00` | `DailyDigestMonitor` | Daily digest send time in local timezone. |
| `monitors.daily_digest.expected_collection_interval` | duration | `00:01:00` | `DailyDigestMonitor` | Expected metrics interval for offline gap detection sensitivity. |
| `tools.<tool>.enabled` | bool | `true` | `Tool` base | Per-tool enable/disable switch. |
| `tools.<tool>.schedule` | `HH:MM` or cron | none | `Scheduler` | Optional recurring schedule. |
| `tools.security_update.dry_run` | bool | `false` | `SecurityUpdateTool` | Simulate updates without changing packages. |
| `tools.security_update.reboot_policy` | string | `notify` | `SecurityUpdateTool` | If not `never`, reboot-required events are emitted when needed. |
| `tools.packages.required` | list[string] | `[]` | `RequiredPackagesTool` | Package list that must stay installed. |
| `updates.self_update.enabled` | bool | `false` at runtime (`true` when setup wizard creates new config) | `SelfUpdateMonitor` | Enables daemon self-update loop. |
| `updates.self_update.check_interval` | duration | `00:05:00` (min effective `00:00:30`) | `SelfUpdateMonitor` | Poll interval for git updates. |
| `updates.self_update.source_path` | path | auto-discovered | `SelfUpdateMonitor` | Preferred key for local repository path. |
| `updates.self_update.remote` | string | `origin` | `SelfUpdateMonitor` | Git remote name. |
| `updates.self_update.branch` | string | `main` | `SelfUpdateMonitor` | Git branch to track. |
| `updates.self_update.reinstall` | bool | `true` | `SelfUpdateMonitor` | Runs `.venv/bin/pip install -e <repo>` after pull when available. |
| *(signal)* `SIGHUP` | n/a | n/a | `run_daemon` | Reloads chat access control from `config.yaml` without restarting the daemon. |
| `updates.enabled` | bool | `true` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `updates.schedule` | `HH:MM` | `02:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `updates.reboot_if_required` | bool | `false` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.cpu.interval` | duration | `00:01:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.ram.interval` | duration | `00:01:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.disk.interval` | duration | `00:05:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.network.interval` | duration | `00:01:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `metrics_export.prometheus.enabled` | bool | none | optional-feature setup merge | Added when enabling `prometheus`; currently no runtime consumer in this repo. |
| `monitors.gpu.enabled` | bool | none | optional-feature setup merge | Added when enabling `gpu`; currently no runtime consumer in this repo. |
| `tools.harden.enabled` | bool | none | optional-feature setup merge | Added when enabling `harden`; currently no runtime consumer in this repo. |
| `tools.snapshot.enabled` | bool | none | optional-feature setup merge | Added when enabling `snapshot`; currently no runtime consumer in this repo. |
| `tools.vulnscan.enabled` | bool | none | optional-feature setup merge | Added when enabling `vulnscan`; currently no runtime consumer in this repo. |

## Runtime-first example

```yaml
chat_adapters:
  discord:
    enabled: true
    token: "your-discord-token"
    channel_id: "123456789012345678"
    unauthorized_response: "deny_message"
    unauthorized_message: "Not authorised."
    allowed_users:
      - id: "111111111111111111"
        role: "admin"
      - id: "222222222222222222"
        role: "readonly"

updates:
  self_update:
    enabled: true
    check_interval: "00:05:00"
    source_path: "/opt/SystemSentinel"
    remote: "origin"
    branch: "main"
    reinstall: true

monitors:
  collection_interval: "00:01:00"
  retention: "30d 00:00:00"
  cpu:
    enabled: true
    alert_threshold_percent: 90
    alert_consecutive_intervals: 2
    alert_cooldown: "00:30:00"
  ram:
    enabled: true
    alert_threshold_percent: 90
    alert_cooldown: "00:30:00"
  disk:
    enabled: true
    alert_threshold_percent: 85
    alert_cooldown: "00:30:00"
  network:
    enabled: true
  logins:
    enabled: true
    failed_login_alert_count: 5
    failed_login_window: "00:10:00"
    alert_cooldown: "00:30:00"
  connections:
    enabled: true
    whitelist: []
    repeat_alert_count: 3
    repeat_alert_window: "00:10:00"
    cooldown: "01:00:00"
  old_files:
    enabled: true
    watched_directories: []
    scan_interval: "24:00:00"
    age_threshold: "30d 00:00:00"
  daily_digest:
    enabled: true
    send_time_local: "08:00"
    expected_collection_interval: "00:01:00"

tools:
  security_update:
    enabled: true
    schedule: "02:00"
    dry_run: false
    reboot_policy: "notify"
  packages:
    enabled: true
    schedule: "0 */6 * * *"
    required:
      - curl
      - git
```
