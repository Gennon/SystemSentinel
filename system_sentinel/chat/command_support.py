from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from system_sentinel.chat.base import InboundMessage, InboundReaction


def command_prefix_for_adapter(
    *,
    config: dict[str, Any],
    adapter_name: str,
    default_prefix: str,
) -> str:
    adapter_cfg = config.get("chat_adapters", {}).get(adapter_name, {})
    if isinstance(adapter_cfg, dict):
        raw = adapter_cfg.get("command_prefix")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return default_prefix


def extract_command(
    *,
    config: dict[str, Any],
    adapter_name: str,
    text: str,
    args: list[str],
    default_prefix: str,
    aliases: dict[str, str],
) -> str | None:
    prefix = command_prefix_for_adapter(
        config=config,
        adapter_name=adapter_name,
        default_prefix=default_prefix,
    )
    token = args[0].strip() if args else text.strip().split(maxsplit=1)[0] if text.strip() else ""
    if not token.startswith(prefix):
        return None
    command = f"!{token[len(prefix) :].lower()}"
    return aliases.get(command, command)


def is_in_command_channel(*, config: dict[str, Any], message: InboundMessage) -> bool:
    chat_cfg = config.get("chat_adapters", {}).get(message.adapter, {})
    if not isinstance(chat_cfg, dict):
        return False
    command_channel_id = chat_cfg.get("command_channel_id", chat_cfg.get("channel_id"))
    if command_channel_id is None:
        return True
    return str(command_channel_id) == message.channel_id


async def record_command(
    *,
    audit: Any,
    message: InboundMessage,
    command: str,
    outcome: str,
    result: str,
) -> None:
    await audit.append(
        action_type="chat_command",
        source=f"chat:{message.adapter}:{message.user_id}",
        description=f"Processed chat command {command}.",
        outcome=outcome,
        details={
            "adapter": message.adapter,
            "channel_id": message.channel_id,
            "user_id": message.user_id,
            "username": message.username,
            "command": command,
            "result": result,
        },
    )


async def record_reaction_command(
    *,
    audit: Any,
    reaction: InboundReaction,
    command: str,
    outcome: str,
    result: str,
    extra_details: dict[str, Any] | None = None,
) -> None:
    details: dict[str, Any] = {
        "adapter": reaction.adapter,
        "channel_id": reaction.channel_id,
        "user_id": reaction.user_id,
        "username": reaction.username,
        "command": command,
        "emoji": str(reaction.emoji),
        "result": result,
    }
    if extra_details:
        details.update(extra_details)
    await audit.append(
        action_type="chat_command",
        source=f"chat:{reaction.adapter}:{reaction.user_id}",
        description=f"Processed confirmed chat command {command}.",
        outcome=outcome,
        details=details,
    )
