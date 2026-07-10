# Chat Adapter Setup Guide

SystemSentinel forwards alerts to chat platforms and listens for commands through **chat adapters**. Each adapter is an optional dependency — install only what you need.

---

## Discord

### 1. Create a Discord bot

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications) and click **New Application**.
2. Give it a name (e.g. `SystemSentinel`) and click **Create**.
3. In the left sidebar, click **Bot**
4. Under **Privileged Gateway Intents**, enable **Message Content Intent**.
5. Click **Reset Token** and copy the token. Store it somewhere safe; you will need it in the next step.

### 2. Invite the bot to your server

1. In the left sidebar, click **OAuth2 → URL Generator**.
2. Under **Scopes**, tick `bot`.
3. Under **Bot Permissions**, tick:
   - **Send Messages**
   - **Embed Links**
   - **Read Message History**
4. Copy the generated URL, open it in your browser.
5. Open a browser and paste the URL. Select your server (SystemSentinel) and click **Authorize**.

### 3. Find your channel ID

1. In Discord, go to **User Settings → Advanced** and enable **Developer Mode**.
2. Right-click the channel you want to use for alerts and select **Copy Channel ID**.

### 4. Find your user ID (for access control)

Right-click your own username in any Discord channel and select **Copy User ID**.
You will use this in the `allowed_users` list so the bot accepts commands from you.

### 5. Install the Discord dependency

```bash
pip install "system-sentinel[discord]"
# or, if using the project venv:
.venv/bin/pip install "system-sentinel[discord]"
```

### 6. Set the bot token as an environment variable

Never commit your token. The recommended approach is an environment variable:

```bash
export SENTINEL_DISCORD_TOKEN="your-bot-token-here"
```

To make this permanent, add the export to `/etc/environment` (system-wide) or your shell profile, or use a systemd `EnvironmentFile`:

```ini
# /etc/systemd/system/system-sentinel.service  (relevant excerpt)
[Service]
EnvironmentFile=/etc/system-sentinel/secrets.env
```

```bash
# /etc/system-sentinel/secrets.env
SENTINEL_DISCORD_TOKEN=your-bot-token-here
```

```bash
chmod 600 /etc/system-sentinel/secrets.env
```

### 7. Configure `config.yaml`

```yaml
chat:
  provider: discord
  command_prefix: "!"           # prefix for bot commands, e.g. !status
  unauthorized_response: silent # silent | deny_message

  discord:
    enabled: true
    token: "env:SENTINEL_DISCORD_TOKEN"   # reads from environment variable
    channel_id: "123456789012345678"

  allowed_users:
    - "YOUR_DISCORD_USER_ID"
    # - "ANOTHER_DISCORD_USER_ID"
```

> **Important:** `allowed_users` must be a list of user ID strings. Do not mix scalar entries with object fields (`platform`, `role`) in the same list item, or YAML parsing/validation will fail.

### 8. Start (or restart) the daemon

```bash
sentinel run
# or, if using systemd:
sudo systemctl restart system-sentinel
```

You should see a log line similar to:
```
INFO  sentinel.chat.discord  Discord bot connected as SystemSentinel#1234
```

### 9. Verify it works

In your alert channel, send:
```
!status
```

The bot should reply with current CPU, RAM, disk usage, uptime, and service health.

---

## Supported commands (Release 2)

| Command | Access | Description |
|---------|--------|-------------|
| `!help` | readonly | Lists all available commands |
| `!status` | readonly | Current CPU, RAM, disk, uptime, and service health |
| `!alerts` | readonly | Currently active alert conditions |
| `!files` | readonly | Lists old files flagged for cleanup |
| `!storage` | readonly | Triggers a storage report |
| `!anomalies` | readonly | Recent login anomalies |
| `!firewall` | readonly | Firewall status |
| `!hardening` | readonly | Hardening audit results |
| `!update` | admin | Triggers an immediate security update (requires ✅ confirmation) |
| `!cleanup` | admin | Triggers an immediate file cleanup (requires ✅ confirmation) |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Bot never comes online | Wrong token or `SENTINEL_DISCORD_TOKEN` not set | Check the env var is exported in the same shell / systemd unit |
| Bot online but no messages | Message Content Intent not enabled | Enable it in the Discord Developer Portal → Bot |
| `ImportError: discord.py is required` | Optional dependency missing | Run `pip install "system-sentinel[discord]"` |
| Commands ignored silently | User not in `allowed_users` | Add your Discord user ID to the list |
| Bot times out on start | Firewall blocking outbound WebSocket | Allow outbound HTTPS/WSS on port 443 |

---

## Other adapters

| Adapter | Status | Install extra |
|---------|--------|--------------|
| Discord | ✅ Available | `pip install "system-sentinel[discord]"` |
| Telegram | 🔜 Planned | `pip install "system-sentinel[telegram]"` |

Guides for additional adapters will be added here as they are implemented.
