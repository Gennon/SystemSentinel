# US-038 — Guided configuration during setup

**Release:** 1 — Core / MVP
**Area:** Communication & Alerts
**Status:** Done

## Description
As a user I want the setup wizard to walk me through the minimum required configuration so I don't have to manually edit a config file to get started.

## Acceptance Criteria
- [x] If no `config.yaml` exists, the wizard prompts for the values that have no safe default:
  - Chat provider type (Discord first; extensible for others)
  - Chat bot token
  - Chat channel ID
  - At least one allowed user ID (per US-034)
- [x] Each prompt includes a short description of what the value is and where to find it
- [x] Each entered value is validated immediately (e.g. the bot token is tested against the chat API, the channel ID is verified as accessible)
- [x] If validation fails, the user is told why and prompted to re-enter the value
- [x] All other config values are set to safe defaults; the wizard tells the user where the config file is saved and how to edit it later
- [x] If a `config.yaml` already exists, the wizard validates it and reports any missing or invalid fields without overwriting user changes
