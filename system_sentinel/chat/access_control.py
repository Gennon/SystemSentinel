from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging

    from system_sentinel.chat.base import InboundMessage
    from system_sentinel.core.context import AuditRepository

_DEFAULT_READONLY_COMMANDS = {
    "!help",
    "!status",
    "!ask",
    "!alerts",
    "!graph",
    "!audit",
    "!connections",
    "!files",
    "!storage",
    "!snapshots",
    "!anomalies",
    "!firewall",
    "!hardening",
    "!vulnscan",
}
_COMMAND_ALIASES = {
    "!snaphsots": "!snapshots",
}

_DEFAULT_UNAUTHORIZED_MESSAGE = "Not authorised."


class UserRole(StrEnum):
    ADMIN = "admin"
    READONLY = "readonly"


@dataclass(frozen=True)
class AdapterPolicy:
    user_roles: dict[str, UserRole]
    readonly_commands: frozenset[str]
    unauthorized_response: str
    unauthorized_message: str


@dataclass(frozen=True)
class AccessDecision:
    authorized: bool
    role: UserRole | None
    respond_with_message: bool
    reason: str


class ChatAccessControl:
    """Authorizes inbound chat interactions based on configured allowed users."""

    def __init__(
        self,
        config: dict[str, Any],
        logger: logging.Logger,
        enabled_adapters: set[str],
    ) -> None:
        self._logger = logger.getChild("chat.access_control")
        self._policies: dict[str, AdapterPolicy] = {}
        self.reload(config, enabled_adapters)

    def reload(self, config: dict[str, Any], enabled_adapters: set[str]) -> None:
        adapters_cfg = config.get("chat_adapters", {})
        if not isinstance(adapters_cfg, dict):
            adapters_cfg = {}

        policies: dict[str, AdapterPolicy] = {}
        for adapter_name in enabled_adapters:
            raw_cfg = adapters_cfg.get(adapter_name, {})
            adapter_cfg = raw_cfg if isinstance(raw_cfg, dict) else {}

            user_roles = self._parse_allowed_users(adapter_name, adapter_cfg.get("allowed_users"))
            readonly_commands = self._parse_readonly_commands(adapter_cfg.get("readonly_commands"))
            unauthorized_response = self._parse_unauthorized_response(
                adapter_name, adapter_cfg.get("unauthorized_response")
            )
            unauthorized_message = self._parse_unauthorized_message(
                adapter_cfg.get("unauthorized_message")
            )

            policies[adapter_name] = AdapterPolicy(
                user_roles=user_roles,
                readonly_commands=readonly_commands,
                unauthorized_response=unauthorized_response,
                unauthorized_message=unauthorized_message,
            )

            if not user_roles:
                self._logger.warning(
                    "No allowed_users configured for chat adapter %r — refusing all chat commands.",
                    adapter_name,
                )

        self._policies = policies

    def authorize(self, message: InboundMessage, args: list[str]) -> AccessDecision:
        policy = self._policies.get(message.adapter)
        if policy is None:
            return AccessDecision(
                authorized=False,
                role=None,
                respond_with_message=False,
                reason="adapter_not_configured",
            )

        role = policy.user_roles.get(message.user_id)
        if role is None:
            return AccessDecision(
                authorized=False,
                role=None,
                respond_with_message=policy.unauthorized_response == "deny_message",
                reason="user_not_allowed",
            )

        if role is UserRole.ADMIN:
            return AccessDecision(
                authorized=True,
                role=role,
                respond_with_message=False,
                reason="authorized",
            )

        command = _extract_command(message.text, args)
        if command is None or command in policy.readonly_commands:
            return AccessDecision(
                authorized=True,
                role=role,
                respond_with_message=False,
                reason="authorized",
            )

        return AccessDecision(
            authorized=False,
            role=role,
            respond_with_message=policy.unauthorized_response == "deny_message",
            reason="readonly_forbidden_command",
        )

    def unauthorized_message_for(self, adapter_name: str) -> str:
        policy = self._policies.get(adapter_name)
        if policy is None:
            return _DEFAULT_UNAUTHORIZED_MESSAGE
        return policy.unauthorized_message

    async def audit_rejection(
        self,
        audit: AuditRepository,
        message: InboundMessage,
        args: list[str],
        reason: str,
    ) -> None:
        attempted = _extract_command(message.text, args) or message.text.strip() or "<empty>"
        await audit.append(
            action_type="chat_command",
            source=f"chat:{message.adapter}:{message.user_id}",
            description="Rejected chat command attempt.",
            outcome="failure",
            details={
                "user_id": message.user_id,
                "username": message.username,
                "command": attempted,
                "reason": reason,
            },
        )

    def _parse_allowed_users(self, adapter_name: str, raw: object) -> dict[str, UserRole]:
        if raw is None:
            return {}
        if not isinstance(raw, list):
            self._logger.warning(
                "Invalid allowed_users for adapter %r: expected a list, got %s.",
                adapter_name,
                type(raw).__name__,
            )
            return {}

        parsed: dict[str, UserRole] = {}
        for item in raw:
            if isinstance(item, str):
                user_id = item.strip()
                if user_id:
                    parsed[user_id] = UserRole.ADMIN
                continue

            if not isinstance(item, dict):
                continue
            raw_id = item.get("id")
            if not isinstance(raw_id, str) or not raw_id.strip():
                continue
            raw_role = item.get("role", UserRole.READONLY.value)
            if not isinstance(raw_role, str):
                continue
            try:
                role = UserRole(raw_role.lower())
            except ValueError:
                self._logger.warning(
                    "Ignoring allowed_users entry for adapter %r with invalid role %r.",
                    adapter_name,
                    raw_role,
                )
                continue
            parsed[raw_id.strip()] = role
        return parsed

    def _parse_readonly_commands(self, raw: object) -> frozenset[str]:
        if raw is None:
            return frozenset(_DEFAULT_READONLY_COMMANDS)
        if not isinstance(raw, list):
            return frozenset(_DEFAULT_READONLY_COMMANDS)

        commands = {
            str(item).strip().lower() for item in raw if isinstance(item, str) and str(item).strip()
        }
        return frozenset(commands) if commands else frozenset(_DEFAULT_READONLY_COMMANDS)

    def _parse_unauthorized_response(self, adapter_name: str, raw: object) -> str:
        if raw is None:
            return "silent"
        if not isinstance(raw, str):
            self._logger.warning(
                "Invalid unauthorized_response for adapter %r: expected string.",
                adapter_name,
            )
            return "silent"
        value = raw.strip().lower()
        if value in {"silent", "deny_message"}:
            return value
        self._logger.warning(
            "Invalid unauthorized_response %r for adapter %r; using 'silent'.",
            raw,
            adapter_name,
        )
        return "silent"

    def _parse_unauthorized_message(self, raw: object) -> str:
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        return _DEFAULT_UNAUTHORIZED_MESSAGE


def _extract_command(text: str, args: list[str]) -> str | None:
    if args:
        candidate = args[0].strip().lower()
        if candidate.startswith("!"):
            return _COMMAND_ALIASES.get(candidate, candidate)
    stripped = text.strip().lower()
    if not stripped.startswith("!"):
        return None
    command = stripped.split(maxsplit=1)[0]
    if not command:
        return None
    return _COMMAND_ALIASES.get(command, command)
