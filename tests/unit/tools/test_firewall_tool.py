from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest

from system_sentinel.core.context import AppContext
from system_sentinel.tools.base import ToolOutcome
from system_sentinel.tools.firewall.backends import (
    FirewallBackend,
    FirewallRule,
    FirewallState,
    UnsupportedFirewallBackendError,
)
from system_sentinel.tools.firewall.tool import FirewallTool


def _make_ctx() -> AppContext:
    audit = AsyncMock()
    audit.append = AsyncMock()
    event_bus = AsyncMock()
    event_bus.publish = AsyncMock()
    return AppContext(
        audit=audit,
        event_bus=event_bus,
        logger=logging.getLogger("test"),
    )


class FakeFirewallBackend(FirewallBackend):
    name = "ufw"

    def __init__(self, states: list[FirewallState]) -> None:
        self._states = states
        self.apply_policy_calls: list[str] = []
        self.ensure_rule_calls: list[FirewallRule] = []
        self.remove_rule_calls: list[FirewallRule] = []

    async def capture_state(self) -> FirewallState:
        if len(self._states) > 1:
            return self._states.pop(0)
        return self._states[0]

    async def apply_default_incoming_policy(self, policy: str) -> None:
        self.apply_policy_calls.append(policy)

    async def ensure_rule(self, rule: FirewallRule) -> None:
        self.ensure_rule_calls.append(rule)

    async def remove_rule(self, rule: FirewallRule) -> None:
        self.remove_rule_calls.append(rule)


def _tool(config: dict[str, Any], backend: FirewallBackend) -> FirewallTool:
    return FirewallTool(config, _make_ctx(), backend=backend)


def _rule(source: str, port: int, protocol: str = "tcp") -> FirewallRule:
    return FirewallRule(source=source, port=port, protocol=protocol)


def test_schedule_converts_reconcile_interval_to_cron() -> None:
    backend = FakeFirewallBackend(
        [
            FirewallState(
                backend="ufw",
                default_incoming_policy="deny",
                allow_rules=(),
                raw_output="state",
            )
        ]
    )
    tool = _tool({"reconcile_interval": "00:10:00"}, backend=backend)
    assert tool.schedule() == "*/10 * * * *"


@pytest.mark.asyncio
async def test_drift_detected_without_enforcement() -> None:
    backend = FakeFirewallBackend(
        [
            FirewallState(
                backend="ufw",
                default_incoming_policy="allow",
                allow_rules=(_rule("any", 22), _rule("any", 8080)),
                raw_output="ufw status",
            )
        ]
    )
    tool = _tool(
        {
            "enforce": False,
            "desired_state": {
                "default_incoming_policy": "deny",
                "allowed_ports": [22],
                "allowed_sources": ["any"],
                "allowed_protocols": ["tcp"],
            },
        },
        backend=backend,
    )

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert "drift detected" in result.summary.lower()
    assert backend.ensure_rule_calls == []
    assert backend.remove_rule_calls == []
    assert backend.apply_policy_calls == []
    event_types = [call.args[0] for call in tool.ctx.event_bus.publish.call_args_list]
    assert "alert.firewall.drift_detected" in event_types


@pytest.mark.asyncio
async def test_enforce_true_applies_policy_and_rules() -> None:
    backend = FakeFirewallBackend(
        [
            FirewallState(
                backend="ufw",
                default_incoming_policy="allow",
                allow_rules=(_rule("any", 22), _rule("any", 8080)),
                raw_output="before",
            ),
            FirewallState(
                backend="ufw",
                default_incoming_policy="deny",
                allow_rules=(_rule("any", 22),),
                raw_output="after",
            ),
        ]
    )
    tool = _tool(
        {
            "enforce": True,
            "desired_state": {
                "default_incoming_policy": "deny",
                "allowed_ports": [22],
                "allowed_sources": ["any"],
                "allowed_protocols": ["tcp"],
            },
        },
        backend=backend,
    )

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert "reconciled" in result.summary.lower()
    assert backend.apply_policy_calls == ["deny"]
    assert backend.remove_rule_calls == [_rule("any", 8080)]
    assert backend.ensure_rule_calls == []


@pytest.mark.asyncio
async def test_no_drift_returns_match_summary() -> None:
    backend = FakeFirewallBackend(
        [
            FirewallState(
                backend="ufw",
                default_incoming_policy="deny",
                allow_rules=(_rule("any", 22),),
                raw_output="state",
            )
        ]
    )
    tool = _tool(
        {
            "enforce": False,
            "desired_state": {
                "default_incoming_policy": "deny",
                "allowed_ports": [22],
                "allowed_sources": ["any"],
                "allowed_protocols": ["tcp"],
            },
        },
        backend=backend,
    )

    result = await tool.run()

    assert result.outcome == ToolOutcome.SUCCESS
    assert "matches desired" in result.summary.lower()
    event_types = [call.args[0] for call in tool.ctx.event_bus.publish.call_args_list]
    assert "alert.firewall.drift_detected" not in event_types


@pytest.mark.asyncio
async def test_status_report_contains_match_state() -> None:
    backend = FakeFirewallBackend(
        [
            FirewallState(
                backend="ufw",
                default_incoming_policy="deny",
                allow_rules=(_rule("any", 22),),
                raw_output="state",
            )
        ]
    )
    tool = _tool(
        {
            "desired_state": {
                "default_incoming_policy": "deny",
                "allowed_ports": [22],
                "allowed_sources": ["any"],
                "allowed_protocols": ["tcp"],
            },
        },
        backend=backend,
    )

    report = await tool.status_report()

    assert "Desired state: MATCH" in report
    assert "any -> 22/tcp" in report


@pytest.mark.asyncio
async def test_unsupported_backend_returns_failure() -> None:
    class UnsupportedBackend(FirewallBackend):
        name = "unsupported"

        async def capture_state(self) -> FirewallState:
            raise UnsupportedFirewallBackendError("not installed")

        async def apply_default_incoming_policy(self, policy: str) -> None:
            raise AssertionError("not used")

        async def ensure_rule(self, rule: FirewallRule) -> None:
            raise AssertionError("not used")

        async def remove_rule(self, rule: FirewallRule) -> None:
            raise AssertionError("not used")

    tool = _tool({}, backend=UnsupportedBackend())
    result = await tool.run()
    assert result.outcome == ToolOutcome.FAILURE
