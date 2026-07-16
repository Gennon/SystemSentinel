# Configuration Reference (`/etc/sentinel/config.yaml`)

This document is the authoritative reference for SystemSentinel configuration keys and examples.

**Maintenance rule:** whenever a key is added, removed, renamed, or behavior/default changes, update this file in the same change.

## Value formats

### Durations

The following keys use duration parsing from `system_sentinel.core.time_config`:

- `HH:MM:SS` (example: `00:05:00`)
- `<days>d HH:MM:SS` (example: `30d 00:00:00`)

### Schedules

Tool schedules accept:

- `HH:MM` (daily at local time), example: `"02:00"`
- Cron expression, example: `"0 */6 * * *"`

### Environment variable references

Any string config value can reference an environment variable using:

- `env:VARIABLE_NAME`

At load time, SystemSentinel replaces the value with the variable contents. If the variable is not set, startup fails with a config error.

## Full configuration example

```yaml
chat_adapters:
  discord:
    enabled: true
    token: "your-discord-token"
    channel_id: "123456789012345678"
    command_channel_id: "123456789012345678"
    command_prefix: "!"
    unauthorized_response: "deny_message"
    unauthorized_message: "Not authorised."
    allowed_users:
      - id: "111111111111111111"
        role: "admin"
      - id: "222222222222222222"
        role: "readonly"

llm:
  enabled: true
  provider: "ollama" # ollama | openai | anthropic | mistral
  remediation: false
  timeout_seconds: 30

llm_providers:
  ollama:
    enabled: true
    endpoint: "http://localhost:11434"
    model: "llama3.2"
  openai:
    enabled: false
    endpoint: "https://api.openai.com"
    api_key: ""
    model: "gpt-4o-mini"
  anthropic:
    enabled: false
    endpoint: "https://api.anthropic.com"
    api_key: ""
    model: "claude-3-5-sonnet-latest"
    api_version: "2023-06-01"
    max_tokens: 1024
  mistral:
    enabled: false
    endpoint: "https://api.mistral.ai"
    api_key: ""
    model: "mistral-large-latest"

dashboard:
  refresh_interval: "00:00:05"

updates:
  self_update:
    enabled: true
    check_interval: "00:05:00"
    source_path: "/opt/SystemSentinel"
    remote: "origin"
    branch: "main"
    reinstall: true
    snapshots:
      backend: "auto"
      keep_last: 20

monitors:
  collection_interval: "00:01:00"
  retention: "30d 00:00:00"
  geoip_database_path: ""
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
    alert_threshold_bytes_sent: 10000000
    alert_threshold_bytes_recv: 10000000
    alert_cooldown: "00:30:00"
  gpu:
    enabled: true
    alert_threshold_utilization_percent: 95
    alert_threshold_temperature_c: 85
    alert_cooldown: "00:30:00"
  logins:
    enabled: true
    failed_login_alert_count: 5
    failed_login_window: "00:10:00"
    alert_cooldown: "00:30:00"
    anomaly_detection:
      brute_force_enabled: true
      off_hours_enabled: true
      new_user_enabled: true
      impossible_travel_enabled: true
      off_hours_start: "07:00"
      off_hours_end: "22:00"
      impossible_travel_window: "02:00:00"
      impossible_travel_min_distance_km: 500
  connections:
    enabled: true
    whitelist: []
    repeat_alert_count: 3
    repeat_alert_window: "00:10:00"
    cooldown: "01:00:00"
    classification:
      attempts_per_ip:
        suspicious: 3
        likely_access_attempt: 8
      distinct_destination_ports:
        suspicious: 2
        likely_access_attempt: 4
      recurrence_over_time:
        window: "24:00:00"
        suspicious: 3
        likely_access_attempt: 7
      protocol_port_sensitivity:
        sensitive_ports: [22, 3389, 5900]
        weight: 2
      score_thresholds:
        suspicious: 3
        likely_access_attempt: 6
      ip_enrichment:
        enabled: false
        enable_reverse_dns: true
        enable_asn_lookup: true
        enable_geoip: true
  services:
    enabled: true
    check_interval: "00:01:00"
    max_restart_attempts: 3
    journal_lines: 20
    critical_services:
      - "sshd.service"
      - "nginx.service"
  old_files:
    enabled: true
    watched_directories:
      - "/tmp"
      - "/var/log"
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
  firewall:
    enabled: true
    reconcile_interval: "00:10:00"
    run_on_startup: true
    enforce: false
    backend: auto
    desired_state:
      default_incoming_policy: deny
      rules:
        - port: 22
          protocol: tcp
          sources: ["any"]
```

## Section guide and focused examples

### Chat adapters

Use `chat_adapters.<adapter>` to configure inbound/outbound chat integration and command access control.

```yaml
chat_adapters:
  discord:
    enabled: true
    token: "your-discord-token"
    channel_id: "123456789012345678"
    command_channel_id: "123456789012345678"
    command_prefix: "!"
    unauthorized_response: "deny_message"
    unauthorized_message: "Not authorised."
    readonly_commands:
      - "!status"
      - "!daily"
      - "!firewall"
    allowed_users:
      - id: "111111111111111111"
        role: "admin"
      - id: "222222222222222222"
        role: "readonly"
```

### LLM assistant

Use `llm` for active-provider selection and defaults, and `llm_providers.<provider>` for provider-specific credentials/endpoints.

```yaml
llm:
  enabled: true
  provider: "anthropic"
  remediation: true
  timeout_seconds: 30

llm_providers:
  ollama:
    enabled: true
    endpoint: "http://localhost:11434"
    model: "llama3.2"
  openai:
    enabled: false
    endpoint: "https://api.openai.com"
    api_key: ""
    model: "gpt-4o-mini"
  anthropic:
    enabled: true
    endpoint: "https://api.anthropic.com"
    api_key: "env:ANTHROPIC_API_KEY"
    model: "claude-3-5-sonnet-latest"
    api_version: "2023-06-01"
    max_tokens: 1024
  mistral:
    enabled: false
    endpoint: "https://api.mistral.ai"
    api_key: ""
    model: "mistral-large-latest"
```

### Monitors

Monitors are grouped under `monitors.*` and run on the global collection loop (`monitors.collection_interval`) unless they have monitor-specific intervals/settings.

#### Resource monitor tuning example

```yaml
monitors:
  collection_interval: "00:01:00"
  retention: "30d 00:00:00"
  cpu:
    enabled: true
    alert_threshold_percent: 92
    alert_consecutive_intervals: 3
    alert_cooldown: "00:20:00"
  ram:
    enabled: true
    alert_threshold_percent: 90
    alert_cooldown: "00:20:00"
  disk:
    enabled: true
    alert_threshold_percent: 88
    alert_cooldown: "00:45:00"
  gpu:
    enabled: true
    alert_threshold_utilization_percent: 95
    alert_threshold_temperature_c: 85
    alert_cooldown: "00:30:00"
```

#### Security monitor tuning example

```yaml
monitors:
  geoip_database_path: "/usr/share/GeoIP/GeoLite2-City.mmdb"
  logins:
    enabled: true
    failed_login_alert_count: 7
    failed_login_window: "00:15:00"
    alert_cooldown: "00:30:00"
    anomaly_detection:
      brute_force_enabled: true
      off_hours_enabled: true
      new_user_enabled: true
      impossible_travel_enabled: true
      off_hours_start: "07:00"
      off_hours_end: "22:00"
      impossible_travel_window: "02:00:00"
      impossible_travel_min_distance_km: 500
  services:
    enabled: true
    check_interval: "00:01:00"
    max_restart_attempts: 2
    journal_lines: 30
    critical_services:
      - "sshd.service"
      - "nginx.service"
  connections:
    enabled: true
    whitelist:
      - "10.0.0.0/8"
      - "192.168.1.10"
    repeat_alert_count: 4
    repeat_alert_window: "00:10:00"
    cooldown: "01:00:00"
```

#### Filesystem and reporting monitor example

```yaml
monitors:
  old_files:
    enabled: true
    watched_directories:
      - "/var/tmp"
      - "/srv/backups"
    scan_interval: "12:00:00"
    age_threshold: "14d 00:00:00"
  daily_digest:
    enabled: true
    send_time_local: "07:30"
    expected_collection_interval: "00:01:00"
```

### Tools

Tools are configured under `tools.<tool_name>` and can be scheduled with `schedule`.

#### `tools.security_update` example

```yaml
tools:
  security_update:
    enabled: true
    schedule: "02:00"
    dry_run: false
    reboot_policy: "notify" # notify | auto | never
```

#### `tools.packages` example

```yaml
tools:
  packages:
    enabled: true
    schedule: "0 */6 * * *"
    required:
      - curl
      - git
      - fail2ban
```

#### `tools.firewall` example (preferred explicit rule format)

```yaml
tools:
  firewall:
    enabled: true
    reconcile_interval: "00:10:00"
    run_on_startup: true
    enforce: false
    backend: auto # auto | ufw | nftables
    desired_state:
      default_incoming_policy: deny
      rules:
        - port: 22
          protocol: tcp
          sources: ["any"]
        - port: 443
          protocol: tcp
          sources:
            - "203.0.113.10"
```

#### `tools.firewall` shorthand example (legacy compatibility)

```yaml
tools:
  firewall:
    enabled: true
    desired_state:
      default_incoming_policy: deny
      allowed_ports: [22, 443]
      allowed_sources: ["any", "203.0.113.10"]
      allowed_protocols: ["tcp"]
```

When `desired_state.rules` is provided, it takes precedence over `allowed_ports`/`allowed_sources`/`allowed_protocols`.

#### `tools.hardening` example

```yaml
tools:
  hardening:
    enabled: true
    run_on_startup: true
    schedule: "7d 00:00:00" # weekly default if omitted
    auto_remediate: false
    benchmarks:
      cis_level_1: true
    checks:
      ssh_disable_root_login: true
      ssh_disable_password_auth: true
      sysctl_hardening: true
      disable_unnecessary_services: true
      strong_password_policy: true
    unnecessary_services:
      - telnet.socket
      - rsh.socket
      - rlogin.socket
      - rexec.socket
    sysctl:
      net.ipv4.conf.all.accept_redirects: "0"
      net.ipv4.conf.default.accept_redirects: "0"
      net.ipv4.conf.all.send_redirects: "0"
      net.ipv4.conf.default.send_redirects: "0"
      net.ipv4.tcp_syncookies: "1"
      kernel.randomize_va_space: "2"
    password_policy:
      minlen: 14
      minclass: 3
```

### Self-update

```yaml
updates:
  self_update:
    enabled: true
    check_interval: "00:05:00"
    source_path: "/opt/SystemSentinel"
    remote: "origin"
    branch: "main"
    reinstall: true
    snapshots:
      backend: "auto" # auto | snapper | timeshift | none
      keep_last: 20
```

## Connection intent classification

The connection monitor classifies unknown inbound activity to help distinguish scanning from attack behavior:

- **`background_scan`** - Low-confidence network noise/scanning
- **`suspicious`** - Medium-confidence targeted probing
- **`likely_access_attempt`** - High-confidence attack behavior

### Heuristic scoring model

Classification score is derived from:

1. Attempts per source IP
2. Distinct destination ports targeted
3. Recurrence over time (separate window, default 24h)
4. Sensitive port targeting (defaults include 22, 3389, 5900)

The resulting score is mapped using `score_thresholds`.

### Optional IP enrichment

When `ip_enrichment.enabled: true`, classification can include:

- Reverse DNS hostname
- ASN/organization lookup (`ipwhois` required)
- GeoIP country (`geoip2` + MaxMind database required)

If enrichment is enabled but lookups fail (or dependencies are missing), enrichment fields are `null`; monitoring continues.

## Complete key map (grouped)

### Chat adapter keys

| Key | Type | Default | Used by | Notes |
|---|---|---|---|---|
| `chat_adapters.<adapter>.enabled` | bool | `false` | `ChatRegistry` | Must be `true` to load an adapter. |
| `chat_adapters.discord.token` | string | none | `DiscordAdapter` | Required when `chat_adapters.discord.enabled=true`. |
| `chat_adapters.discord.channel_id` | string/int | none | `DiscordAdapter` | Default destination channel for outgoing messages. |
| `chat_adapters.<adapter>.command_channel_id` | string/int | `channel_id` | `ChatCommandDispatcher` | Restricts where commands are accepted; falls back to `channel_id` if unset. |
| `chat_adapters.<adapter>.command_prefix` | string | `!` | `ChatCommandDispatcher` | Prefix used to parse commands for that adapter. |
| `chat_adapters.<adapter>.allowed_users` | list[string \| object] | `[]` | `ChatAccessControl` | String entry = admin. Object entry = `{id, role}` with `admin` or `readonly`. |
| `chat_adapters.<adapter>.unauthorized_response` | string | `silent` | `ChatAccessControl` | `silent` or `deny_message`. |
| `chat_adapters.<adapter>.unauthorized_message` | string | `Not authorised.` | `ChatAccessControl` | Used when `unauthorized_response=deny_message`. |
| `chat_adapters.<adapter>.readonly_commands` | list[string] | built-in readonly set | `ChatAccessControl` | Allowed commands for `readonly` users. |

### LLM keys

| Key | Type | Default | Used by | Notes |
|---|---|---|---|---|
| `llm.enabled` | bool | `false` | `LLMClient` | Global LLM enable flag. |
| `llm.provider` | string | first loaded provider | `LLMClient` | Active provider key (must match an enabled `llm_providers.<name>`). |
| `llm.remediation` | bool | `false` | `AlertHandler` | When `true`, critical alert notifications trigger an advisory-only AI follow-up message. |
| `llm.timeout_seconds` | int/float | `30` | callers (e.g. chat `!ask`, alert remediation) | Request timeout preference; call sites may override. |
| `llm_providers.<provider>.enabled` | bool | `false` | `LLMRegistry` | Must be `true` to load provider plugin. |
| `llm_providers.ollama.endpoint` | string | `http://localhost:11434` | `OllamaProvider` | Ollama base URL. |
| `llm_providers.ollama.model` | string | unset | `OllamaProvider` | Fallback model when request/model default is absent. |
| `llm_providers.openai.endpoint` | string | `https://api.openai.com` | `OpenAIProvider` | OpenAI-compatible base URL. |
| `llm_providers.openai.api_key` | string | none | `OpenAIProvider` | Required for authenticated OpenAI calls. |
| `llm_providers.openai.model` | string | unset | `OpenAIProvider` | Fallback model when request/model default is absent. |
| `llm_providers.anthropic.endpoint` | string | `https://api.anthropic.com` | `AnthropicProvider` | Anthropic API base URL. |
| `llm_providers.anthropic.api_key` | string | none | `AnthropicProvider` | Required for authenticated Anthropic calls. |
| `llm_providers.anthropic.model` | string | unset | `AnthropicProvider` | Fallback model when request/model default is absent. |
| `llm_providers.anthropic.api_version` | string | `2023-06-01` | `AnthropicProvider` | Sent as `anthropic-version` header. |
| `llm_providers.anthropic.max_tokens` | int | `1024` | `AnthropicProvider` | Upper bound for generated tokens per request. |
| `llm_providers.mistral.endpoint` | string | `https://api.mistral.ai` | `MistralProvider` | Mistral API base URL. |
| `llm_providers.mistral.api_key` | string | none | `MistralProvider` | Required for authenticated Mistral calls. |
| `llm_providers.mistral.model` | string | unset | `MistralProvider` | Fallback model when request/model default is absent. |

### Monitor keys

| Key | Type | Default | Used by | Notes |
|---|---|---|---|---|
| `monitors.collection_interval` | duration | `00:01:00` | `MonitorRegistry` | Global monitor collection loop interval. |
| `monitors.retention` | duration | `30d 00:00:00` | `MonitorRegistry` | Metric retention window (daily purge). |
| `monitors.geoip_database_path` | path | `""` | `LoginMonitor`, `ConnectionMonitor` | Canonical GeoIP DB path shared across monitors. |
| `monitors.<monitor>.enabled` | bool | `true` | `MonitorRegistry`/`BaseMonitor` | Per-monitor enable/disable switch. |
| `monitors.cpu.data_dir` | path | `/var/lib/sentinel` | `CpuMonitor` | Used to locate `sentinel.db`. |
| `monitors.cpu.alert_threshold_percent` | number | `90` | `CpuMonitor` | CPU usage alert threshold. |
| `monitors.cpu.alert_consecutive_intervals` | int | `2` | `CpuMonitor` | Fires after this many consecutive high samples (strictly greater than this value). |
| `monitors.cpu.alert_cooldown` | duration | `00:30:00` | `CpuMonitor` | Minimum time between CPU alerts. |
| `monitors.ram.data_dir` | path | `/var/lib/sentinel` | `RamMonitor` | Used to locate `sentinel.db`. |
| `monitors.ram.alert_threshold_percent` | number | `90` | `RamMonitor` | RAM usage alert threshold. |
| `monitors.ram.alert_cooldown` | duration | `00:30:00` | `RamMonitor` | Minimum time between RAM alerts. |
| `monitors.disk.data_dir` | path | `/var/lib/sentinel` | `DiskMonitor` | Used to locate `sentinel.db`. |
| `monitors.disk.alert_threshold_percent` | number | `85` | `DiskMonitor` | Disk usage alert threshold per mountpoint. |
| `monitors.disk.alert_cooldown` | duration | `00:30:00` | `DiskMonitor` | Minimum time between disk alerts (per mountpoint). |
| `monitors.network.data_dir` | path | `/var/lib/sentinel` | `NetworkMonitor` | Used to locate `sentinel.db`. |
| `monitors.network.alert_threshold_bytes_sent` | number | unset | `NetworkMonitor` | Optional per-interval sent-bytes threshold; if unset, sent alerts are disabled. |
| `monitors.network.alert_threshold_bytes_recv` | number | unset | `NetworkMonitor` | Optional per-interval received-bytes threshold; if unset, receive alerts are disabled. |
| `monitors.network.alert_cooldown` | duration | `00:30:00` | `NetworkMonitor` | Cooldown between network throughput alerts. |
| `monitors.gpu.data_dir` | path | `/var/lib/sentinel` | `GpuMonitor` | Used to locate `sentinel.db`. |
| `monitors.gpu.alert_threshold_utilization_percent` | number | `95` | `GpuMonitor` | GPU utilization threshold (uses peak utilization across detected GPUs). |
| `monitors.gpu.alert_threshold_temperature_c` | number | `85` | `GpuMonitor` | GPU temperature threshold in Celsius (uses hottest detected GPU). |
| `monitors.gpu.alert_cooldown` | duration | `00:30:00` | `GpuMonitor` | Cooldown between GPU threshold alerts. |
| `monitors.logins.data_dir` | path | `/var/lib/sentinel` | `LoginMonitor` | Used to locate `sentinel.db`. |
| `monitors.logins.failed_login_alert_count` | int | `5` | `LoginMonitor` | Brute-force alert threshold. |
| `monitors.logins.failed_login_window` | duration | `00:10:00` | `LoginMonitor` | Brute-force detection window. |
| `monitors.logins.alert_cooldown` | duration | `00:30:00` | `LoginMonitor` | Minimum time between alerts per source IP. |
| `monitors.logins.anomaly_detection.brute_force_enabled` | bool | `true` | `LoginMonitor` | Enables/disables brute-force anomaly alerts. |
| `monitors.logins.anomaly_detection.off_hours_enabled` | bool | `true` | `LoginMonitor` | Enables/disables off-hours successful-login alerts. |
| `monitors.logins.anomaly_detection.new_user_enabled` | bool | `true` | `LoginMonitor` | Enables/disables first-seen user successful-login alerts. |
| `monitors.logins.anomaly_detection.impossible_travel_enabled` | bool | `true` | `LoginMonitor` | Enables/disables impossible-travel detection. |
| `monitors.logins.anomaly_detection.off_hours_start` | `HH:MM` | `07:00` | `LoginMonitor` | Off-hours window start (inclusive). |
| `monitors.logins.anomaly_detection.off_hours_end` | `HH:MM` | `22:00` | `LoginMonitor` | Off-hours window end (inclusive). |
| `monitors.logins.anomaly_detection.impossible_travel_window` | duration | `02:00:00` | `LoginMonitor` | Max interval between successful logins to consider impossible travel. |
| `monitors.logins.anomaly_detection.impossible_travel_min_distance_km` | float | `500` | `LoginMonitor` | Minimum great-circle distance threshold for impossible-travel alerts. |
| `monitors.connections.data_dir` | path | `/var/lib/sentinel` | `ConnectionMonitor` | Used to locate `sentinel.db`. |
| `monitors.connections.whitelist` | list[string] | `[]` | `ConnectionMonitor` | Entries can be IPs or CIDR ranges. |
| `monitors.connections.repeat_alert_count` | int | `3` | `ConnectionMonitor` | Repeated-attempt alert threshold. |
| `monitors.connections.repeat_alert_window` | duration | `00:10:00` | `ConnectionMonitor` | Window for `repeat_alert_count`. |
| `monitors.connections.cooldown` | duration | `01:00:00` | `ConnectionMonitor` | Alert cooldown per source IP. |
| `monitors.connections.classification.attempts_per_ip.suspicious` | int | `3` | `ConnectionMonitor` | Threshold for `suspicious` classification. |
| `monitors.connections.classification.attempts_per_ip.likely_access_attempt` | int | `8` | `ConnectionMonitor` | Threshold for `likely_access_attempt` classification. |
| `monitors.connections.classification.distinct_destination_ports.suspicious` | int | `2` | `ConnectionMonitor` | Threshold for `suspicious` classification. |
| `monitors.connections.classification.distinct_destination_ports.likely_access_attempt` | int | `4` | `ConnectionMonitor` | Threshold for `likely_access_attempt` classification. |
| `monitors.connections.classification.recurrence_over_time.window` | duration | `24:00:00` | `ConnectionMonitor` | Window for recurrence counting. |
| `monitors.connections.classification.recurrence_over_time.suspicious` | int | `3` | `ConnectionMonitor` | Recurrence threshold for `suspicious`. |
| `monitors.connections.classification.recurrence_over_time.likely_access_attempt` | int | `7` | `ConnectionMonitor` | Recurrence threshold for `likely_access_attempt`. |
| `monitors.connections.classification.protocol_port_sensitivity.sensitive_ports` | list[int] | `[22, 3389, 5900]` | `ConnectionMonitor` | Ports that increase classification score. |
| `monitors.connections.classification.protocol_port_sensitivity.weight` | int | `2` | `ConnectionMonitor` | Score boost for sensitive port targeting. |
| `monitors.connections.classification.score_thresholds.suspicious` | int | `3` | `ConnectionMonitor` | Score threshold for `suspicious`. |
| `monitors.connections.classification.score_thresholds.likely_access_attempt` | int | `6` | `ConnectionMonitor` | Score threshold for `likely_access_attempt`. |
| `monitors.connections.classification.ip_enrichment.enabled` | bool | `false` | `ConnectionMonitor` | Enables IP enrichment (optional dependencies). |
| `monitors.connections.classification.ip_enrichment.enable_reverse_dns` | bool | `true` | `ConnectionMonitor` | Reverse DNS enrichment flag. |
| `monitors.connections.classification.ip_enrichment.enable_asn_lookup` | bool | `true` | `ConnectionMonitor` | ASN enrichment flag (`ipwhois`). |
| `monitors.connections.classification.ip_enrichment.enable_geoip` | bool | `true` | `ConnectionMonitor` | GeoIP enrichment flag (`geoip2`). |
| `monitors.services.critical_services` | list[string] | `[]` | `ServiceMonitor` | Critical systemd units to check/restart. |
| `monitors.services.services` | list[string] | `[]` | `ServiceMonitor` | Legacy alias for `critical_services`; used if `critical_services` is not set. |
| `monitors.services.check_interval` | duration | `00:01:00` | `ServiceMonitor` | Service health-check interval. |
| `monitors.services.max_restart_attempts` | int | `3` | `ServiceMonitor` | Max restart retries before escalation. |
| `monitors.services.journal_lines` | int | `20` | `ServiceMonitor` | Journal lines included in notifications. |
| `monitors.old_files.data_dir` | path | `/var/lib/sentinel` | `OldFilesMonitor` | Used to locate `sentinel.db`. |
| `monitors.old_files.watched_directories` | list[path] | `[]` | `OldFilesMonitor` | Empty list disables scanning (with warning). |
| `monitors.old_files.scan_interval` | duration | `24:00:00` | `OldFilesMonitor` | Time between scans. |
| `monitors.old_files.age_threshold` | duration | `30d 00:00:00` | `OldFilesMonitor` | Minimum file age to include. |
| `monitors.directory_changes.data_dir` | path | `/var/lib/sentinel` | `DirectoryChangesMonitor` | Used to locate `sentinel.db`. |
| `monitors.directory_changes.watched_directories` | list[string/object] | `[]` | `DirectoryChangesMonitor` | List of string paths or objects (`{path, whitelist_globs?, whitelist_regex?}`) to monitor recursively. |
| `monitors.directory_changes.alert_cooldown` | duration | `00:05:00` | `DirectoryChangesMonitor` | Per-file-path alert cooldown to avoid storming. |
| `monitors.daily_digest.data_dir` | path | `/var/lib/sentinel` | `DailyDigestMonitor` | Used to locate `sentinel.db`. |
| `monitors.daily_digest.send_time_local` | `HH:MM` | `08:00` | `DailyDigestMonitor` | Daily digest send time (local timezone). |
| `monitors.daily_digest.expected_collection_interval` | duration | `00:01:00` | `DailyDigestMonitor` | Used for offline gap detection sensitivity. |

### Tool keys

| Key | Type | Default | Used by | Notes |
|---|---|---|---|---|
| `tools.<tool>.enabled` | bool | `true` | `Tool` base | Per-tool enable/disable switch. |
| `tools.<tool>.schedule` | `HH:MM`, `HH:MM:SS`, `<days>d HH:MM:SS`, or cron | none | `Scheduler` | Optional recurring schedule (duration expressions use interval triggers). |
| `tools.security_update.dry_run` | bool | `false` | `SecurityUpdateTool` | Simulate updates without changing packages. |
| `tools.security_update.reboot_policy` | string | `notify` | `SecurityUpdateTool` | If not `never`, reboot-required events are emitted when needed. |
| `tools.packages.required` | list[string] | `[]` | `RequiredPackagesTool` | Package list that must stay installed. |
| `tools.cleanup.rules` | list[object] | none | `ChatCommandDispatcher` | Used by confirmed cleanup chat action (`!cleanup now`) when configured. |
| `tools.storage.paths` | list[path] | none | `ChatCommandDispatcher`, `StorageReportTool` | Preferred path list for `!storage` and scheduled storage reports; falls back to `monitors.old_files.watched_directories` then `/` for chat, and `/` for the scheduled tool. |
| `tools.storage.alert_threshold_percent` | float | `85` | `ChatCommandDispatcher`, `StorageReportTool` | Paths above this used-percent are flagged as `ALERT` in storage reports. |
| `tools.firewall.enabled` | bool | `true` | `FirewallTool` | Enables declarative firewall drift detection/reconciliation. |
| `tools.firewall.reconcile_interval` | duration | none | `FirewallTool` | Preferred schedule; converted to cron (falls back to `tools.firewall.schedule` if missing/invalid). |
| `tools.firewall.run_on_startup` | bool | `false` | daemon startup runner | Runs firewall reconciliation on daemon start. |
| `tools.firewall.enforce` | bool | `false` | `FirewallTool` | If `true`, applies desired state; if `false`, drift is alert-only. |
| `tools.firewall.backend` | string | `auto` | setup/systemd installer | Chooses sudoers scope (`auto`, `ufw`, `nftables`). |
| `tools.firewall.desired_state.default_incoming_policy` | string | unset | `FirewallTool` | Incoming default policy (`deny` or `allow`). |
| `tools.firewall.desired_state.allowed_ports` | list[int] | `[]` | `FirewallTool` | Legacy shorthand allow-rule ports list. |
| `tools.firewall.desired_state.allowed_sources` | list[string] | `["any"]` | `FirewallTool` | Legacy shorthand sources list. |
| `tools.firewall.desired_state.allowed_protocols` | list[string] | `["tcp"]` | `FirewallTool` | Legacy shorthand protocols list. |
| `tools.firewall.desired_state.rules` | list[object] | `[]` | `FirewallTool` | Preferred explicit format (`{port, protocol?, sources?}`). |
| `tools.hardening.enabled` | bool | `true` | `HardeningTool` | Enables CIS-style hardening audit/remediation tool. |
| `tools.hardening.run_on_startup` | bool | `true` | daemon startup runner | Runs hardening audit once during daemon start. |
| `tools.hardening.schedule` | duration (`HH:MM:SS` or `<days>d HH:MM:SS`) | `7d 00:00:00` | `HardeningTool` | Recurring hardening audit schedule (weekly default). |
| `tools.hardening.auto_remediate` | bool | `false` | `HardeningTool` | When `true`, failing checks are auto-fixed and chat-notified per item. |
| `tools.hardening.benchmarks.cis_level_1` | bool | `true` | `HardeningTool` | Enables the baseline Level 1 check bundle. |
| `tools.hardening.checks.<check_id>` | bool | bundle default | `HardeningTool` | Per-check overrides (`ssh_disable_root_login`, `ssh_disable_password_auth`, `sysctl_hardening`, `disable_unnecessary_services`, `strong_password_policy`). |
| `tools.hardening.unnecessary_services` | list[string] | distro-sensitive default list | `HardeningTool` | Services/socket units that must remain disabled. |
| `tools.hardening.sysctl` | map[string,string] | built-in secure defaults | `HardeningTool` | Desired kernel parameter baseline for audit/remediation. |
| `tools.hardening.password_policy.minlen` | int | `14` | `HardeningTool` | Minimum password length target. |
| `tools.hardening.password_policy.minclass` | int | `3` | `HardeningTool` | Minimum required password character classes. |

### Update and runtime control keys

| Key | Type | Default | Used by | Notes |
|---|---|---|---|---|
| `dashboard.refresh_interval` | duration (`HH:MM:SS` or `<days>d HH:MM:SS`) | `00:00:05` | `sentinel dashboard` / `sentinel-tui` | Dashboard refresh interval (can be overridden by CLI option `--refresh-interval`). |
| `updates.self_update.enabled` | bool | `false` at runtime (`true` when setup wizard creates config) | `SelfUpdateMonitor` | Enables daemon self-update loop. |
| `updates.self_update.check_interval` | duration | `00:05:00` (min effective `00:00:30`) | `SelfUpdateMonitor` | Git update polling interval. |
| `updates.self_update.source_path` | path | auto-discovered | `SelfUpdateMonitor` | Preferred key for local repo path. |
| `updates.self_update.remote` | string | `origin` | `SelfUpdateMonitor` | Git remote name. |
| `updates.self_update.branch` | string | `main` | `SelfUpdateMonitor` | Git branch to track. |
| `updates.self_update.reinstall` | bool | `true` | `SelfUpdateMonitor` | Runs `.venv/bin/pip install -e <repo>` after pull when available. |
| `updates.self_update.snapshots.backend` | string | `auto` | `SelfUpdateMonitor` + `SnapshotManager` | `auto` probes `snapper` then `timeshift`; `none` disables snapshots. |
| `updates.self_update.snapshots.keep_last` | int | `20` | `SnapshotManager` | Max snapshots retained before pruning oldest. |
| *(signal)* `SIGHUP` | n/a | n/a | `run_daemon` | Reloads chat access control from `config.yaml` without daemon restart. |

### Setup wizard defaults and optional-feature merge keys

These keys are currently setup-only or merge-only (not consumed by runtime code in this repo):

| Key | Type | Default | Used by | Notes |
|---|---|---|---|---|
| `updates.enabled` | bool | `true` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `updates.schedule` | `HH:MM` | `02:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `updates.reboot_if_required` | bool | `false` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.cpu.interval` | duration | `00:01:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.ram.interval` | duration | `00:01:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.disk.interval` | duration | `00:05:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `monitors.network.interval` | duration | `00:01:00` (wizard default) | setup wizard default only | Currently not consumed by runtime code. |
| `metrics_export.prometheus.enabled` | bool | none | optional-feature setup merge | Added when enabling `prometheus`; currently no runtime consumer. |
| `updates.self_update.snapshots.backend` | string | none | optional-feature setup merge | Added as `auto` when enabling `snapshot`. |
| `tools.vulnscan.enabled` | bool | none | optional-feature setup merge | Added when enabling `vulnscan`; currently no runtime consumer. |
