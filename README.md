# SystemSentinel

A Linux system management daemon that autonomously handles updates, security hardening, monitoring, and user communication — surfacing insights and alerts via chat and a local LLM assistant.

## Quick start

```bash
pip install -e ".[discord]"
cp config/config.example.yaml config.yaml   # edit tokens and thresholds
sentinel setup                              # first-time wizard
sentinel run                                # start the daemon
```

## Documentation

| Document | Purpose |
|----------|---------|
| [USER_STORY_MAP.md](USER_STORY_MAP.md) | What we're building and why — source of truth for features and releases |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Package structure, plugin interfaces, coding standards, and how to add tools/adapters/providers |
| [user_stories/](user_stories/) | Detailed acceptance criteria per feature |

## Tech stack

Python · SQLite · APScheduler · Discord · Ollama (local LLM) · systemd

## Development

```bash
pip install -e ".[discord]"
pytest                  # run tests
mypy --strict system_sentinel   # type check
```

New feature? Start with the relevant user story in `user_stories/`, write tests first, then implement. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full developer guide.
