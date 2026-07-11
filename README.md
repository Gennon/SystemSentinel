# SystemSentinel

A Linux system management daemon that autonomously handles updates, security hardening, monitoring, and user communication — surfacing insights and alerts via chat and a local LLM assistant.

## Installation

**Prerequisites:** curl (pre-installed on most Linux distributions)

### One-command installation (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/Gennon/SystemSentinel/main/install.sh | bash
```

This will:
1. Check and install Python 3.11+ (if needed)
2. Check and install git (if needed)
3. Clone the repository
4. Create a Python virtualenv
5. Install SystemSentinel and dependencies
6. Launch the interactive setup wizard (chat config, auto-update choice, and update source path)

### Manual installation

If you prefer to install step-by-step:

```bash
git clone https://github.com/Gennon/SystemSentinel.git
cd SystemSentinel
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[discord]"
sentinel setup                 # first-time wizard
sentinel run                   # start the daemon
```

### Dry-run mode

To see what the installer will do without making changes:

```bash
curl -fsSL https://raw.githubusercontent.com/Gennon/SystemSentinel/main/install.sh | bash -s -- --dry-run
```

## Documentation

| Document | Purpose |
|----------|---------|
| [USER_STORY_MAP.md](USER_STORY_MAP.md) | What we're building and why — source of truth for features and releases |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Package structure, plugin interfaces, coding standards, and how to add tools/adapters/providers |
| [user_stories/](user_stories/) | Detailed acceptance criteria per feature |
| [docs/chat-adapters.md](docs/chat-adapters.md) | How to set up Discord (and future) chat adapters |

## Tech stack

Python · SQLite · APScheduler · Discord · Ollama (local LLM) · systemd

## Development

```bash
pip install -e ".[discord]"
pytest                  # run tests
mypy --strict system_sentinel   # type check
```

New feature? Start with the relevant user story in `user_stories/`, write tests first, then implement. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full developer guide.
