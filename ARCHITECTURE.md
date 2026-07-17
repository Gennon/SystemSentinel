# SystemSentinel — Architecture & Coding Standards

## 1. Directory and Package Structure

```
system_sentinel/                         # Root Python package
├── __init__.py
├── __main__.py                          # Entry point: python -m system_sentinel
│
├── core/                                # Foundational infrastructure
│   ├── __init__.py
│   ├── daemon.py                        # Main daemon lifecycle (start/stop/reload)
│   ├── scheduler.py                     # APScheduler-based job registry
│   ├── event_bus.py                     # In-process publish/subscribe bus
│   ├── config.py                        # Config loader, validator, live-reload
│   ├── context.py                       # AppContext: wires all components together
│   └── exceptions.py                    # Sentinel-specific exception hierarchy
│
├── db/                                  # Persistence layer
│   ├── __init__.py
│   ├── connection.py                    # SQLite connection pool / migrations
│   ├── audit_repository.py
│   ├── metrics_repository.py
│   └── migrations/
│       ├── 0001_initial.sql
│       └── 0002_add_gpu_metrics.sql
│
├── tools/                               # Agent Engine — plugin point #1
│   ├── __init__.py
│   ├── base.py                          # BaseTool ABC
│   ├── registry.py                      # Auto-discovers and registers tools
│   ├── update/
│   │   ├── __init__.py
│   │   └── tool.py                      # SecurityUpdateTool
│   ├── harden/
│   │   ├── __init__.py
│   │   ├── tool.py                      # HardenTool
│   │   └── checks/                      # Individual hardening checks
│   │       ├── base.py                  # BaseHardeningCheck ABC
│   │       ├── ssh_check.py
│   │       ├── sysctl_check.py
│   │       ├── services_check.py
│   │       └── twofa_check.py           # 2FA enforcement audit (US-027)
│   ├── cleanup/
│   │   ├── __init__.py
│   │   └── tool.py                      # CleanupTool
│   ├── packages/
│   │   ├── __init__.py
│   │   └── tool.py                      # RequiredPackagesTool
│   ├── snapshot/
│   │   ├── __init__.py
│   │   └── tool.py                      # SnapshotTool (US-011); backend: auto | snapper | timeshift
│   ├── firewall/
│   │   ├── __init__.py
│   │   └── tool.py                      # FirewallTool (US-014); backend: auto-detected ufw or nftables
│   ├── storage/
│   │   ├── __init__.py
│   │   └── tool.py                      # StorageTool (US-019)
│   └── vulnscan/
│       ├── __init__.py
│       └── tool.py                      # VulnScanTool (US-026); wraps Lynis if installed
│
├── monitors/                            # Monitor Engine — sensor plugins
│   ├── __init__.py
│   ├── base.py                          # BaseMonitor ABC
│   ├── registry.py
│   ├── cpu.py
│   ├── ram.py
│   ├── disk.py
│   ├── network.py
│   ├── gpu.py
│   ├── logins.py
│   ├── connections.py                   # Inbound connection monitor (US-004)
│   ├── services.py                      # Systemd service health monitor (US-012)
│   └── file_integrity.py
│
├── alerts/                              # Alert evaluation, deduplication, routing
│   ├── __init__.py
│   ├── evaluator.py                     # Compares metrics against thresholds
│   ├── cooldown.py                      # Suppresses repeat alerts within cooldown window
│   └── models.py                        # Alert dataclass
│
├── chat/                                # Notification Engine — plugin point #2
│   ├── __init__.py
│   ├── base.py                          # BaseChatAdapter ABC
│   ├── registry.py
│   ├── router.py                        # Routes events to correct adapters
│   ├── command_dispatcher.py            # Maps !commands to tool handlers
│   ├── access_control.py               # allowed_users enforcement
│   ├── digest_builder.py               # Builds daily/weekly digest messages
│   └── adapters/
│       ├── discord/
│       │   ├── __init__.py
│       │   └── adapter.py              # DiscordAdapter
│       ├── telegram/                    # (future)
│       └── slack/                       # (future)
│
├── llm/                                 # LLM Interface — plugin point #3
│   ├── __init__.py
│   ├── base.py                          # BaseLLMProvider ABC
│   ├── client.py                        # Active-provider facade
│   ├── registry.py
│   ├── context_builder.py              # Gathers system context for prompts
│   └── providers/
│       ├── ollama/
│       │   ├── __init__.py
│       │   └── provider.py             # OllamaProvider
│       ├── openai/
│       │   ├── __init__.py
│       │   └── provider.py             # OpenAIProvider
│       ├── anthropic/
│       │   ├── __init__.py
│       │   └── provider.py             # AnthropicProvider
│       └── mistral/
│           ├── __init__.py
│           └── provider.py             # MistralProvider
│
├── charts/                              # Chart rendering — plugin point #4 (Release 3)
│   ├── __init__.py
│   ├── base.py                          # BaseChartRenderer ABC
│   ├── registry.py
│   └── renderers/
│       ├── text/
│       │   ├── __init__.py
│       │   └── renderer.py              # TextChartRenderer (plotext, default)
│       └── image/
│           ├── __init__.py
│           └── renderer.py              # ImageChartRenderer (matplotlib, optional)
│
├── metrics_export/                      # Optional Prometheus exporter (Release 3)
│   ├── __init__.py
│   └── http_server.py
│
├── setup/                               # First-time setup wizard
│   ├── __init__.py
│   ├── wizard.py
│   ├── dependency_installer.py
│   └── systemd_installer.py
│
└── cli/                                 # CLI entry points
    ├── __init__.py
    └── main.py                          # Click-based: sentinel run / setup / status

tests/
├── conftest.py                          # Shared fixtures, fake AppContext
├── unit/
│   ├── tools/
│   ├── monitors/
│   ├── alerts/
│   ├── chat/
│   └── llm/
└── integration/
    ├── test_scheduler_integration.py
    └── test_sqlite_repositories.py

config/
└── config.example.yaml

packaging/
└── sentinel.service                     # systemd unit template
```

---

## 2. Plugin Interfaces

There are three extension points. Each follows the same pattern: an abstract base class, a registry that discovers implementations via Python entry points, and dependency injection via `AppContext`.

### 2.1 Tools (`tools/base.py`)

A tool is a unit of work the Agent Engine runs on a schedule or on demand via a chat command.

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

class ToolOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED  = "skipped"

@dataclass
class ToolResult:
    tool_name: str
    outcome: ToolOutcome
    summary: str                         # One-line human description
    details: dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    error: str | None = None

class BaseTool(ABC):
    name: str                            # Unique snake_case identifier
    display_name: str                    # Human label shown in chat and logs
    description: str                     # One sentence shown in !help

    def __init__(self, config: "ToolConfig", app_ctx: "AppContext") -> None:
        self.config = config
        self.ctx = app_ctx
        self.logger = app_ctx.logger.getChild(self.name)

    @abstractmethod
    async def run(self) -> ToolResult:
        """Execute the tool's main action. Must be idempotent."""
        ...

    async def dry_run(self) -> ToolResult:
        """Simulate execution without making changes. Default: delegates to run()."""
        return await self.run()

    def is_enabled(self) -> bool:
        return self.config.get("enabled", True)

    def schedule(self) -> str | None:
        """Cron expression or HH:MM string. None disables automatic scheduling."""
        return self.config.get("schedule")
```

Rules:
- `run()` must never raise. Failures are expressed in `ToolResult.outcome = FAILURE`.
- Tools receive `AppContext` at construction and use it for all side effects (DB, events, logging).
- Schedule and chat-command binding are declared on the tool, not hard-coded in the scheduler.

### 2.2 Chat Adapters (`chat/base.py`)

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, Awaitable

class AlertSeverity(str, Enum):
    INFO     = "info"
    WARNING  = "warning"
    CRITICAL = "critical"

@dataclass
class InboundMessage:
    adapter: str                         # e.g. "discord"
    channel_id: str
    user_id: str
    username: str
    text: str
    raw: object                          # Adapter-native message object
    received_at: datetime

@dataclass
class OutboundMessage:
    text: str
    title: str | None = None
    severity: AlertSeverity = AlertSeverity.INFO
    fields: dict[str, str] | None = None  # Structured embeds / cards
    reply_to: InboundMessage | None = None

CommandHandler = Callable[[InboundMessage, list[str]], Awaitable[OutboundMessage | None]]

class BaseChatAdapter(ABC):
    name: str                            # Unique identifier matching config key

    def __init__(self, config: "ChatConfig", app_ctx: "AppContext") -> None:
        self.config = config
        self.ctx = app_ctx
        self.logger = app_ctx.logger.getChild(f"chat.{self.name}")

    @abstractmethod
    async def start(self) -> None:
        """Connect and begin listening. Called once on daemon start."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Disconnect cleanly."""
        ...

    @abstractmethod
    async def send(self, channel_id: str, message: OutboundMessage) -> None:
        """Send a message to a specific channel."""
        ...

    @abstractmethod
    async def send_to_default(self, message: OutboundMessage) -> None:
        """Send to the adapter's configured default alert channel."""
        ...

    def on_message(self, handler: CommandHandler) -> None:
        """Register the dispatcher callback. Called by ChatRouter during wiring."""
        self._message_handler = handler
```

Rules:
- Adapters own the connection lifecycle but never interpret commands directly.
- All inbound messages are handed off to `CommandDispatcher` unchanged.
- Adapters have no dependency on tools or monitors — they are pure I/O.
- Adapters implement exponential backoff reconnect; connection loss is not a daemon crash.

### 2.3 LLM Providers (`llm/base.py`)

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class LLMRequest:
    prompt: str
    system_prompt: str | None = None
    model: str | None = None             # Override config default
    timeout_seconds: int = 30

@dataclass
class LLMResponse:
    text: str
    model_used: str
    provider: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None

class LLMUnavailableError(Exception):
    """Raised when the provider cannot be reached."""

class BaseLLMProvider(ABC):
    name: str                            # Unique identifier matching config key

    def __init__(self, config: "LLMConfig", app_ctx: "AppContext") -> None:
        self.config = config
        self.ctx = app_ctx
        self.logger = app_ctx.logger.getChild(f"llm.{self.name}")

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a prompt and return a response. Raises LLMUnavailableError on failure."""
        ...

    @abstractmethod
    async def list_models(self) -> list[str]:
        """Return available model names. Raises LLMUnavailableError on failure."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the provider is reachable and a model is loaded."""
        ...
```

### 2.4 Chart Renderers (`charts/base.py`)

```python
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

class ChartPeriod(str, Enum):
    H24  = "24h"
    D7   = "7d"
    D30  = "30d"
    D90  = "90d"

@dataclass
class ChartRequest:
    metric: str                          # e.g. "cpu", "ram", "disk"
    period: ChartPeriod
    data: list[tuple[str, float]]        # (ISO timestamp, value) pairs

@dataclass
class ChartResult:
    content_type: str                    # "text" or "image/png"
    payload: str | bytes                 # unicode string or PNG bytes

class BaseChartRenderer(ABC):
    name: str                            # Unique identifier matching config value

    @abstractmethod
    async def render(self, request: ChartRequest) -> ChartResult:
        """Render a chart and return the result."""
        ...
```

Two built-in renderers:

| Renderer | `name` | Output | Extra | Default |
|----------|--------|--------|-------|---------|
| `TextChartRenderer` | `text` | Unicode chart in a code block | none (`plotext` is a core dep) | yes |
| `ImageChartRenderer` | `image` | PNG bytes attached to the message | `pip install system-sentinel[graphs]` (`matplotlib`) | no |

Selected via `charts.renderer: text` (or `image`) in `config.yaml`. Switching renderers requires no code changes. `OutboundMessage` already supports file attachments via `fields`; the chat adapter is responsible for attaching PNG bytes as a file when `content_type` is `image/png`.

---

## 3. Core Components

### 3.1 AppContext (`core/context.py`)

`AppContext` is the single dependency injection container passed through the entire system. Nothing imports global state.

```python
@dataclass
class AppContext:
    config: ConfigManager
    db: DatabaseConnection
    audit: AuditRepository
    metrics: MetricsRepository
    event_bus: EventBus
    scheduler: Scheduler
    tool_registry: ToolRegistry
    monitor_registry: MonitorRegistry
    chat_router: ChatRouter
    llm: BaseLLMProvider | None
    logger: logging.Logger
```

All subsystems receive `AppContext` at construction. Unit tests build a fake `AppContext` with mock repositories.

### 3.2 ConfigManager (`core/config.py`)

- Loads and validates `config.yaml` via `pydantic` models at startup.
- Watches the file with `watchdog` and re-validates on change.
- Emits `config.config.reloaded` on success; emits `config.config.reload_failed` and preserves the last-good config on validation failure.
- Expands `env:VAR_NAME` values to environment variable contents at load time.
- Provides typed accessors: `config.tools.update`, `config.chat`, `config.llm`.

### 3.3 EventBus (`core/event_bus.py`)

A lightweight asyncio-native publish/subscribe bus. Components communicate exclusively through events; no direct cross-component method calls in the hot path.

Event type naming convention: `<domain>.<noun>.<past_tense_verb>`

```
metrics.cpu.collected
alert.disk.fired
alert.disk.resolved
tool.update.started
tool.update.completed
config.config.reloaded
chat.message.received
digest.daily.scheduled
digest.weekly.scheduled
```

```python
class EventBus:
    async def publish(self, event_type: str, payload: Any) -> None: ...
    def subscribe(self, event_type: str, handler: Callable) -> None: ...
    def subscribe_pattern(self, pattern: str, handler: Callable) -> None: ...
        # e.g. subscribe_pattern("alert.*.*", handler)
```

The bus uses asyncio queues internally. Handlers are fire-and-forget coroutines. Unhandled exceptions in subscribers are logged and do not propagate.

### 3.4 Scheduler (`core/scheduler.py`)

Thin wrapper around APScheduler's `AsyncIOScheduler`:
- Registers jobs from each tool's `schedule()` at startup.
- Provides `schedule_once(tool_name, delay_seconds=0)` for chat-triggered runs.
- Persists next-run times across restarts via APScheduler's SQLite job store.
- Submits scheduled jobs as events (`tool.<name>.scheduled`) rather than calling tools directly, maintaining the event-driven model.

### 3.5 Daemon Lifecycle (`core/daemon.py`)

**start()**
1. Load and validate config
2. Run database migrations
3. Wire `AppContext`
4. Start event bus
5. Auto-discover and register tools, monitors, chat adapters
6. Start scheduler (registers all tool schedules)
7. Start chat adapter(s) (begins listening)
8. Start monitor collection loop
9. Emit `daemon.started`
10. Block on `asyncio.run()`

**stop()** — triggered by `SIGTERM` / `SIGINT`
1. Emit `daemon.stopping`
2. Stop scheduler (wait for running jobs to finish, max 30s)
3. Stop chat adapters
4. Close DB connections
5. Exit cleanly

Config hot-reload is triggered by `SIGHUP`: re-validates config, updates live references via `ConfigReloadedEvent`, no restart required.

---

## 4. Data Flow

### 4.1 Metric Collection → Alert → Chat

```
MonitorRegistry
  └── CpuMonitor.collect()  [every 60s]
        ├── stores MetricSample in MetricsRepository (SQLite)
        └── publishes  metrics.cpu.collected  { value: 94.2, ... }
                │
                ▼
        AlertEvaluator  [subscribed to metrics.*.collected]
          │  compares value against configured thresholds
          │  checks CooldownManager
          │
          ├── threshold breached + not cooling down:
          │     publishes  alert.cpu.fired  { Alert }
          │           ├── AuditRepository.append(...)
          │           └── ChatRouter → DiscordAdapter.send_to_default(OutboundMessage)
          │
          └── condition resolved:
                publishes  alert.cpu.resolved  { Alert }
```

### 4.2 Inbound Chat Command → Tool Execution → Reply

```
DiscordAdapter
  └── on message received:
        publishes  chat.message.received  { InboundMessage }
                │
                ▼
        AccessControl
          ├── rejected: AuditRepository.append(rejected_command)
          └── approved:
                publishes  chat.command.authorized  { InboundMessage }
                      │
                      ▼
                CommandDispatcher
                  ├── !ask <question>  → LLMContextBuilder + LLMProvider → reply
                  └── !update          → confirmation prompt
                                         publishes  tool.update.run_requested
                                               │
                                               ▼
                                         Scheduler.schedule_once("update")
                                               │
                                               ▼
                                         SecurityUpdateTool.run() → ToolResult
                                               │
                                               ▼
                                         publishes  tool.update.completed
                                               ├── AuditRepository.append(...)
                                               └── ChatRouter → reply
```

### 4.3 Scheduled Digest

```
Scheduler  [fires daily at configured time]
  └── publishes  digest.daily.scheduled
                │
                ▼
        DigestBuilder  [subscribed]
          │  queries MetricsRepository (24h aggregates)
          │  queries AuditRepository (recent actions)
          │  queries AlertEvaluator (fired alerts)
          └── publishes  digest.daily.ready  { OutboundMessage }
                    │
                    ▼
            ChatRouter → all configured adapters → send to digest channel
```

---

## 5. Configuration Schema

`config.yaml` is validated by pydantic v2 at startup. Every key has a documented default.

```yaml
daemon:
  log_level: info           # debug | info | warning | error
  log_file: /var/log/sentinel/sentinel.log
  data_dir: /var/lib/sentinel
  audit_log: /var/log/sentinel/audit.log
  config_reload: true

tools:
  update:
    enabled: true
    schedule: "02:00"       # HH:MM or cron expression
    dry_run: false
    reboot_policy: notify   # notify | auto | never

  harden:
    enabled: true
    schedule: "0 3 * * 0"
    auto_remediate: false
    checks:
      - ssh
      - sysctl
      - services

  cleanup:
    enabled: true
    schedule: "0 4 * * *"
    rules:
      - path: /tmp
        older_than: "7d 00:00:00"
        pattern: "*"
      - path: /var/log
        older_than: "30d 00:00:00"
        pattern: "*.gz"

  packages:
    enabled: true
    required:
      - curl
      - ufw
      - fail2ban

  firewall:
    enabled: true
    reconcile_interval: "00:10:00"
    run_on_startup: true
    enforce: false
    backend: auto            # auto | ufw | nftables
    desired_state:
      default_incoming_policy: deny
      allowed_ports: [22]
      allowed_sources: [any]
      allowed_protocols: [tcp]

monitors:
  collection_interval: "00:01:00"
  retention: "90d 00:00:00"
  cpu:
    enabled: true
    alert_threshold_percent: 90
    alert_consecutive_intervals: 2
  ram:
    enabled: true
    alert_threshold_percent: 90
  disk:
    enabled: true
    alert_threshold_percent: 85
    exclude_mounts:
      - /boot/efi
  network:
    enabled: true
  gpu:
    enabled: auto           # auto: enable only if GPU detected
  logins:
    enabled: true
    failed_login_alert_count: 5
    failed_login_window: "00:10:00"
  file_integrity:
    enabled: false
    watched_paths:
      - /etc/ssh
      - /etc/sudoers

charts:
  renderer: "text"             # text | image

alerts:
  notify_min_severity: info  # info | warning | critical (chat suppression threshold)
  cooldown_minutes: 30
  severity_levels:
    cpu_high: warning
    ram_high: warning
    disk_full: critical
    login_brute_force: critical
    unknown_ip: warning
  quiet_hours:
    enabled: false
    start: "22:00"
    end: "07:00"
    suppress_severities:
      - info
      - warning

chat:
  provider: discord          # Must match a key below
  command_prefix: "!"
  unauthorized_response: silent   # silent | deny_message

  discord:
    token: "env:SENTINEL_DISCORD_TOKEN"   # env: prefix reads from environment
    alert_channel_id: ""
    digest_channel_id: ""

  # telegram:                # Future adapter — same structure pattern
  #   token: "env:SENTINEL_TELEGRAM_TOKEN"
  #   chat_id: ""

  allowed_users:
    - id: "123456789"
      platform: discord
      role: admin            # admin | readonly
    - id: "987654321"
      platform: discord
      role: readonly

  digest:
    enabled: true
    time: "08:00"

llm:
  enabled: true
  provider: "ollama"         # ollama | openai | anthropic | mistral
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
    api_key: "env:OPENAI_API_KEY"
    model: "gpt-4o-mini"
  anthropic:
    enabled: false
    endpoint: "https://api.anthropic.com"
    api_key: "env:ANTHROPIC_API_KEY"
    model: "claude-3-5-sonnet-latest"
    api_version: "2023-06-01"
  mistral:
    enabled: false
    endpoint: "https://api.mistral.ai"
    api_key: "env:MISTRAL_API_KEY"
    model: "mistral-large-latest"

metrics_export:
  prometheus:
    enabled: false
    port: 9100
    bearer_token: ""
```

The `env:VAR_NAME` prefix is supported anywhere in the schema. `ConfigManager` expands it at load time so secrets are never written to disk in plaintext.

---

## 6. Database Schema

### `audit_log`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | Auto-increment |
| `timestamp` | TEXT | ISO 8601 UTC |
| `action_type` | TEXT | `tool_run`, `alert_fired`, `chat_command`, `config_reload`, `llm_query` |
| `source` | TEXT | `scheduler`, `chat:discord:user123`, `daemon` |
| `description` | TEXT | Human-readable one-liner |
| `outcome` | TEXT | `success`, `failure`, `skipped` |
| `details_json` | TEXT | JSON blob for structured data |

The `audit_log` table is append-only. A SQLite trigger rejects any `UPDATE` or `DELETE`.

### `metrics`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `timestamp` | TEXT | ISO 8601 UTC |
| `metric_name` | TEXT | e.g. `cpu.overall`, `disk./home.used_percent` |
| `value` | REAL | |
| `host` | TEXT | Hostname (for future multi-host support) |

### `alerts`

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `fired_at` | TEXT | ISO 8601 UTC |
| `resolved_at` | TEXT | NULL if still active |
| `metric_name` | TEXT | |
| `severity` | TEXT | `info`, `warning`, `critical` |
| `threshold` | REAL | |
| `observed_value` | REAL | |
| `notified` | INTEGER | 0 / 1 |

---

## 7. Auto-Discovery

Tools, monitors, chat adapters, and LLM providers are auto-discovered via Python entry points in `pyproject.toml`. Third-party packages can ship their own plugins and they are available immediately after `pip install` — no changes to core code required.

```toml
[project.entry-points."sentinel.tools"]
security_update = "system_sentinel.tools.update.tool:SecurityUpdateTool"
harden          = "system_sentinel.tools.harden.tool:HardenTool"
cleanup         = "system_sentinel.tools.cleanup.tool:CleanupTool"
packages        = "system_sentinel.tools.packages.tool:RequiredPackagesTool"
snapshot        = "system_sentinel.tools.snapshot.tool:SnapshotTool"
firewall        = "system_sentinel.tools.firewall.tool:FirewallTool"
storage         = "system_sentinel.tools.storage.tool:StorageTool"
vulnscan        = "system_sentinel.tools.vulnscan.tool:VulnScanTool"

[project.entry-points."sentinel.monitors"]
cpu             = "system_sentinel.monitors.cpu:CpuMonitor"
ram             = "system_sentinel.monitors.ram:RamMonitor"
disk            = "system_sentinel.monitors.disk:DiskMonitor"
network         = "system_sentinel.monitors.network:NetworkMonitor"
gpu             = "system_sentinel.monitors.gpu:GpuMonitor"
logins          = "system_sentinel.monitors.logins:LoginMonitor"
connections     = "system_sentinel.monitors.connections:ConnectionMonitor"
services        = "system_sentinel.monitors.services:ServiceMonitor"
file_integrity  = "system_sentinel.monitors.file_integrity:FileIntegrityMonitor"

[project.entry-points."sentinel.chat_adapters"]
discord = "system_sentinel.chat.adapters.discord.adapter:DiscordAdapter"

[project.entry-points."sentinel.llm_providers"]
ollama = "system_sentinel.llm.providers.ollama.provider:OllamaProvider"
openai = "system_sentinel.llm.providers.openai.provider:OpenAIProvider"
anthropic = "system_sentinel.llm.providers.anthropic.provider:AnthropicProvider"
mistral = "system_sentinel.llm.providers.mistral.provider:MistralProvider"
```

Each registry loads its group with `importlib.metadata.entry_points(group="sentinel.tools")` at daemon startup.

---

## 8. Coding Standards

### 8.1 Naming Conventions

| Entity | Convention | Example |
|--------|-----------|---------|
| Packages | `snake_case` | `chat/adapters/discord/` |
| Modules | `snake_case` | `context_builder.py` |
| Classes | `PascalCase` | `SecurityUpdateTool`, `DiscordAdapter` |
| Functions / methods | `snake_case` | `async def run()` |
| Constants | `UPPER_SNAKE_CASE` | `DEFAULT_COOLDOWN_MINUTES = 30` |
| Type aliases | `PascalCase` | `CommandHandler` |
| Event type strings | `<domain>.<noun>.<past_tense_verb>` | `"alert.cpu.fired"` |
| Config YAML keys | `snake_case` | `collection_interval` |
| Tool `name` attribute | `snake_case` | `"security_update"` |

### 8.2 Type Hints

All production code uses full type annotations. `mypy --strict` runs in CI.

- Use `from __future__ import annotations` in all modules to avoid circular import issues with forward references.
- Use `X | None` over `Optional[X]` (Python 3.10+ union syntax).
- Use `TypedDict` or pydantic models for structured payloads — no bare `dict[str, Any]` crossing module boundaries.
- `Any` is permitted only inside adapter wrappers where the upstream library's type system is incomplete (e.g. raw discord.py event objects).

### 8.3 Async Model

The daemon runs in a single asyncio event loop.

- All I/O (network, file, subprocess) must be `async` or run in a thread pool via `asyncio.to_thread()`.
- CPU-bound work uses `asyncio.to_thread()`.
- No `time.sleep()` anywhere — use `asyncio.sleep()`.
- Blocking subprocess calls use `asyncio.create_subprocess_exec()`.
- `asyncio.run()` is called only in `__main__.py`, never inside the application.

### 8.4 Error Handling

Exception hierarchy in `core/exceptions.py`:

```
SentinelError                          # Base
├── ConfigError                        # Bad config.yaml
├── ToolError                          # Tool execution failure
│   └── ToolPermissionError
├── MonitorError                       # Metric collection failure
├── ChatAdapterError                   # Adapter connection failure
│   └── ChatAuthError
├── LLMUnavailableError
└── DatabaseError
```

Rules:
- **Tools** catch all exceptions internally and return `ToolResult(outcome=FAILURE)`. They never propagate.
- **Monitors** log and continue; one bad metric never stops the collection loop.
- **Chat adapters** implement exponential backoff reconnect. Connection loss is not a crash.
- **EventBus** catches and logs subscriber exceptions; a broken handler never kills the bus.
- `ConfigError` at startup is fatal and exits with code 1.
- `ConfigError` on live reload is non-fatal; the last-good config is preserved.

### 8.5 Logging

Standard library `logging` with structured formatting:

```
2026-06-10T08:00:00Z [INFO ] tool.security_update  Update run started
2026-06-10T08:00:12Z [INFO ] tool.security_update  3 packages updated: curl openssh-server ufw
2026-06-10T08:00:12Z [ERROR] monitor.cpu            psutil.cpu_percent raised OSError: permission denied
```

Rules:
- Logger names follow the module hierarchy: `sentinel.tool.security_update`, `sentinel.chat.discord`.
- `debug` for internal state; `info` for lifecycle events; `warning` for recoverable problems; `error` for failures; `critical` only for things that will stop the daemon.
- No `print()` statements in production code.
- Log messages are plain English sentences.
- Sensitive data (tokens, passwords, user IDs) is never logged at any level.

### 8.6 No Shell Injection

All subprocess calls use `asyncio.create_subprocess_exec()` with a list of arguments. `shell=True` is forbidden.

### 8.7 Subprocess and System Commands

Avoid shelling out to system utilities when a Python library provides the same capability (e.g. use `psutil` instead of parsing `top` output). When a shell command is the only option, use `asyncio.create_subprocess_exec()` with a fully qualified path (e.g. `/usr/bin/apt-get`), never rely on `$PATH`.

---

## 9. Testing

Framework: `pytest` + `pytest-asyncio`.

### Unit tests — `tests/unit/`

- Every `BaseTool` subclass has a unit test with a fake `AppContext`.
- Every `BaseMonitor` subclass has a unit test where `psutil` (or equivalent) is mocked.
- Every `BaseChatAdapter` has a unit test where the upstream library is mocked.
- Every `BaseLLMProvider` has a unit test against a mock HTTP server (`aioresponses` or `pytest-httpx`).
- Alert evaluator tests cover: threshold not breached, threshold breached, cooldown suppression, resolution.

### Integration tests — `tests/integration/`

- Use a real SQLite file in a `tmp_path` fixture — no mocking the database.
- Confirm scheduler fires a job and the result appears in the audit table.
- Confirm config reload: write new YAML, signal reload, assert new values are live.

### Coverage target

90% for `core/`, `tools/`, `monitors/`, `alerts/`. Chat adapters and LLM providers are excluded from the coverage gate (they are contract-tested against mocked networks).

### Fixture pattern

All tests use the `fake_app_context` fixture from `tests/conftest.py`. Never build `AppContext` inline in a test.

---

## 10. How to Add a New Tool

1. Create `system_sentinel/tools/<name>/tool.py` with a class extending `BaseTool`.
2. Set `name`, `display_name`, `description` as class attributes.
3. Implement `async def run(self) -> ToolResult`. Use `self.config`, `self.ctx.audit`, `self.ctx.event_bus`.
4. Add an entry to `pyproject.toml` under `[project.entry-points."sentinel.tools"]`.
5. Add a config section `tools.<name>:` in `config.example.yaml` with at least `enabled` and `schedule`.
6. Add a pydantic config model and reference it from the root `Config` model.
7. Write a unit test in `tests/unit/tools/test_<name>_tool.py` using `fake_app_context`.
8. Register any chat commands by decorating handlers with `@dispatcher.command("!yourcommand")`.

No changes to `daemon.py`, `scheduler.py`, or any other core file are needed.

---

## 11. How to Add a New Chat Integration

1. Create `system_sentinel/chat/adapters/<platform>/adapter.py` with a class extending `BaseChatAdapter`.
2. Set `name` (e.g. `"telegram"`).
3. Implement `start()`, `stop()`, `send()`, `send_to_default()`.
4. In `start()`, wire the platform's incoming message callback to call `self._message_handler(InboundMessage(...))`.
5. Map the platform-native message object to `InboundMessage` (store the original in `raw=`).
6. Add an entry to `pyproject.toml` under `[project.entry-points."sentinel.chat_adapters"]`.
7. Add a config section `chat.<platform>:` in `config.example.yaml`.
8. Add a pydantic config model and reference it from `ChatConfig`.
9. Write unit tests with the platform SDK mocked.

`AccessControl`, `CommandDispatcher`, `DigestBuilder`, and `AlertEvaluator` require zero changes — they work with `InboundMessage` and `OutboundMessage` exclusively.

Guard the platform import:

```python
def __init__(self, config, app_ctx):
    try:
        import discord
    except ImportError:
        raise ChatAdapterError(
            "discord.py is not installed. Run: pip install system-sentinel[discord]"
        )
```

---

## 12. How to Add a New LLM Provider

1. Create `system_sentinel/llm/providers/<provider>/provider.py` with a class extending `BaseLLMProvider`.
2. Set `name` (e.g. `"openai"`).
3. Implement `complete()`, `list_models()`, `health_check()`. Raise `LLMUnavailableError` on connection failure. Never put error text in `LLMResponse.text`.
4. Add an entry to `pyproject.toml` under `[project.entry-points."sentinel.llm_providers"]`.
5. Add a config section `llm.<provider>:` in `config.example.yaml`.
6. Add a pydantic config model.
7. Write unit tests using a mocked HTTP client.

`LLMContextBuilder`, the `!ask` command handler, and audit logging require zero changes.

---

## 13. Optional Dependencies

```toml
[project.optional-dependencies]
discord    = ["discord.py>=2.0"]
telegram   = ["python-telegram-bot>=20"]
gpu        = ["gputil", "pynvml"]
prometheus = ["prometheus_client"]
tui        = ["rich", "textual"]
geoip      = ["geoip2"]
graphs     = ["matplotlib"]
all        = [
    "discord.py>=2.0",
    "python-telegram-bot>=20",
    "gputil",
    "pynvml",
    "prometheus_client",
    "rich",
    "textual",
    "geoip2",
    "matplotlib",
]
```

Core required dependencies:

| Package | Purpose |
|---------|---------|
| `pydantic>=2` | Config validation and typed models |
| `apscheduler>=3.10` | Scheduling with SQLite job store |
| `aiosqlite` | Async SQLite |
| `psutil` | CPU, RAM, disk, network metrics |
| `watchdog` | Config file change detection |
| `click` | CLI entry points |
| `pyyaml` | Config file parsing |
| `httpx` | Async HTTP client (Ollama and other HTTP-based providers) |
| `plotext` | Lightweight unicode chart rendering (text chart renderer) |

### IP Geolocation (impossible travel detection)

The `geoip` optional extra adds `geoip2`, which reads a locally installed **MaxMind GeoLite2** `.mmdb` database file. This keeps IP lookups fully offline — no network calls at runtime.

- The database file path is configured via `monitors.logins.geoip_db_path` in `config.yaml`.
- If the path is not set or the file is absent, the impossible travel check is silently disabled; all other anomaly checks continue normally.
- GeoLite2 is free but requires a one-time registration at maxmind.com to download. The setup wizard (US-035) offers to download it during optional feature setup.
- Install: `pip install system-sentinel[geoip]`

---

## 14. Privilege Escalation

The daemon runs as a dedicated `sentinel` user with no broad root access. Features that require elevated privileges use targeted `sudoers` rules installed by the setup wizard.

```
# /etc/sudoers.d/sentinel  (installed by `sentinel setup`)
sentinel ALL=(root) NOPASSWD: /bin/systemctl restart *
sentinel ALL=(root) NOPASSWD: /bin/systemctl stop *
sentinel ALL=(root) NOPASSWD: /bin/ufw *
sentinel ALL=(root) NOPASSWD: /usr/sbin/ufw *
sentinel ALL=(root) NOPASSWD: /bin/nft *
sentinel ALL=(root) NOPASSWD: /usr/sbin/nft *
```

Rules:
- Only the tools that require elevation get a sudoers entry; unrelated tools have no elevated access.
- Sudoers entries are only written if the corresponding feature (services, firewall) is enabled in `config.yaml`.
- All privileged subprocess calls use `asyncio.create_subprocess_exec()` with a fully qualified path — never `shell=True`.
- The setup wizard writes `/etc/sudoers.d/sentinel` using `visudo -c` to validate before installing; it does not edit `/etc/sudoers` directly.

---

## 15. Security Baseline

- **No shell injection**: `asyncio.create_subprocess_exec()` with argument lists only. `shell=True` is forbidden.
- **Principle of least privilege**: the systemd unit runs as a dedicated `sentinel` user. Capabilities (e.g. `CAP_NET_ADMIN`) are granted only for the specific tools that require them and only when those tools are enabled.
- **Secrets via environment**: all tokens and API keys are read from environment variables using the `env:` config prefix. They are never stored in `config.yaml` in plaintext.
- **Access control by default**: if `allowed_users` is empty at startup, the chat bot refuses all commands and logs a `CRITICAL` warning. There is no open-by-default mode.
- **Append-only audit log**: a SQLite trigger on `audit_log` rejects any `UPDATE` or `DELETE`.
- **Config reload on signal only**: config reloads on `SIGHUP` or an inotify event — not on a polling timer — reducing the attack surface of config injection.
