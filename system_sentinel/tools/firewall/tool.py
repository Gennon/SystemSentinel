from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from system_sentinel.core.time_config import parse_duration_hhmmss
from system_sentinel.tools.base import BaseTool, ToolOutcome, ToolResult
from system_sentinel.tools.firewall.backends import (
    FirewallBackend,
    FirewallBackendError,
    FirewallRule,
    FirewallState,
    UnsupportedFirewallBackendError,
    detect_backend,
)

if TYPE_CHECKING:
    from system_sentinel.core.context import AppContext


class FirewallTool(BaseTool):
    name = "firewall"
    display_name = "Firewall"
    description = "Reconciles firewall state against declarative desired-state configuration."

    def __init__(
        self,
        config: dict[str, Any],
        app_ctx: AppContext,
        backend: FirewallBackend | None = None,
    ) -> None:
        super().__init__(config, app_ctx)
        self._backend = backend

    def _get_backend(self) -> FirewallBackend:
        return self._backend if self._backend is not None else detect_backend()

    def schedule(self) -> str | None:
        interval_expr = self.config.get("reconcile_interval")
        if interval_expr is None:
            return super().schedule()
        parsed = parse_duration_hhmmss(interval_expr)
        if parsed is None:
            self.ctx.logger.getChild("tool.firewall").warning(
                "Invalid firewall reconcile_interval %r; falling back to schedule.",
                interval_expr,
            )
            return super().schedule()
        interval_seconds, _is_non_canonical = parsed
        if interval_seconds <= 0:
            self.ctx.logger.getChild("tool.firewall").warning(
                "Invalid firewall reconcile_interval %r; falling back to schedule.",
                interval_expr,
            )
            return super().schedule()
        return _cron_from_interval_seconds(interval_seconds)

    async def run(self) -> ToolResult:
        started_at = datetime.now(UTC)
        enforce = bool(self.config.get("enforce", False))
        desired_policy = self._desired_default_incoming_policy()
        desired_rules = self._desired_allow_rules()

        try:
            backend = self._get_backend()
            before_state = await backend.capture_state()
            missing_rules, unexpected_rules = _calculate_rule_drift(
                live=before_state.allow_rules,
                desired=desired_rules,
            )
            policy_drift = _policy_drift(
                live_policy=before_state.default_incoming_policy,
                desired_policy=desired_policy,
            )
            drift_detected = bool(missing_rules or unexpected_rules or policy_drift)

            if drift_detected:
                await self._publish_drift_alert(
                    backend_name=backend.name,
                    missing_rules=missing_rules,
                    unexpected_rules=unexpected_rules,
                    live_policy=before_state.default_incoming_policy,
                    desired_policy=desired_policy,
                    enforce=enforce,
                )

            applied_changes: list[str] = []
            if enforce and drift_detected:
                if policy_drift and desired_policy is not None:
                    await backend.apply_default_incoming_policy(desired_policy)
                    applied_changes.append(f"default_incoming_policy={desired_policy}")
                for rule in unexpected_rules:
                    await backend.remove_rule(rule)
                    applied_changes.append(f"remove {rule.source} {rule.port}/{rule.protocol}")
                for rule in missing_rules:
                    await backend.ensure_rule(rule)
                    applied_changes.append(f"add {rule.source} {rule.port}/{rule.protocol}")
                after_state = await backend.capture_state()
            else:
                after_state = before_state

        except UnsupportedFirewallBackendError as exc:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="No supported firewall backend detected.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
            await self._record(result)
            return result
        except FirewallBackendError as exc:
            result = ToolResult(
                tool_name=self.name,
                outcome=ToolOutcome.FAILURE,
                summary="Firewall reconciliation failed while running backend commands.",
                started_at=started_at,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
            await self._record(result)
            return result

        summary = _build_summary(
            drift_detected=drift_detected,
            enforce=enforce,
            missing_count=len(missing_rules),
            unexpected_count=len(unexpected_rules),
        )
        details: dict[str, Any] = {
            "backend": backend.name,
            "enforce": enforce,
            "desired": {
                "default_incoming_policy": desired_policy,
                "allow_rules": [_rule_to_dict(rule) for rule in desired_rules],
            },
            "drift": {
                "detected": drift_detected,
                "missing_rules": [_rule_to_dict(rule) for rule in missing_rules],
                "unexpected_rules": [_rule_to_dict(rule) for rule in unexpected_rules],
                "policy_drift": policy_drift,
            },
            "before_state": _state_to_dict(before_state),
            "after_state": _state_to_dict(after_state),
            "applied_changes": applied_changes,
        }

        result = ToolResult(
            tool_name=self.name,
            outcome=ToolOutcome.SUCCESS,
            summary=summary,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            details=details,
        )
        await self._record(result)
        return result

    async def status_report(self) -> str:
        backend = self._get_backend()
        state = await backend.capture_state()
        desired_policy = self._desired_default_incoming_policy()
        desired_rules = self._desired_allow_rules()
        missing_rules, unexpected_rules = _calculate_rule_drift(
            live=state.allow_rules,
            desired=desired_rules,
        )
        policy_drift = _policy_drift(
            live_policy=state.default_incoming_policy,
            desired_policy=desired_policy,
        )
        drift_detected = bool(missing_rules or unexpected_rules or policy_drift)

        lines: list[str] = [
            f"Firewall backend: {state.backend}",
            (
                "Desired state: MATCH"
                if not drift_detected
                else f"Desired state: DRIFT (missing={len(missing_rules)}, unexpected={len(unexpected_rules)})"
            ),
            (
                f"Default incoming policy: live={state.default_incoming_policy or 'unknown'} "
                f"desired={desired_policy or 'unset'}"
            ),
            "Effective allow rules:",
        ]
        if not state.allow_rules:
            lines.append("- (none)")
        else:
            for rule in sorted(
                state.allow_rules, key=lambda item: (item.source, item.port, item.protocol)
            ):
                lines.append(f"- {rule.source} -> {rule.port}/{rule.protocol}")
        return "\n".join(lines)

    def _desired_allow_rules(self) -> tuple[FirewallRule, ...]:
        desired = self.config.get("desired_state", {})
        desired_cfg = desired if isinstance(desired, dict) else {}
        rules_raw = desired_cfg.get("rules", [])
        parsed_rules: set[FirewallRule] = set()

        if isinstance(rules_raw, list):
            for raw in rules_raw:
                if not isinstance(raw, dict):
                    continue
                port = raw.get("port")
                if not isinstance(port, int):
                    continue
                protocol_raw = raw.get("protocol", "tcp")
                protocol = str(protocol_raw).strip().lower() or "tcp"
                sources = raw.get("sources", ["any"])
                if not isinstance(sources, list) or not sources:
                    sources = ["any"]
                for source_raw in sources:
                    source = str(source_raw).strip() or "any"
                    parsed_rules.add(
                        FirewallRule(
                            source=source.lower() if source == "any" else source,
                            port=port,
                            protocol=protocol,
                        )
                    )

        if parsed_rules:
            return tuple(
                sorted(parsed_rules, key=lambda item: (item.source, item.port, item.protocol))
            )

        ports_raw = desired_cfg.get("allowed_ports", [])
        sources_raw = desired_cfg.get("allowed_sources", ["any"])
        protocols_raw = desired_cfg.get("allowed_protocols", ["tcp"])
        if not isinstance(ports_raw, list):
            return ()
        ports = [int(port) for port in ports_raw if isinstance(port, int)]
        sources = (
            [str(source).strip() for source in sources_raw]
            if isinstance(sources_raw, list)
            else ["any"]
        )
        protocols = (
            [str(proto).strip().lower() for proto in protocols_raw]
            if isinstance(protocols_raw, list)
            else ["tcp"]
        )

        if not sources:
            sources = ["any"]
        if not protocols:
            protocols = ["tcp"]

        for port in ports:
            for source in sources:
                normalized_source = source if source and source.lower() != "any" else "any"
                for protocol in protocols:
                    normalized_protocol = protocol or "tcp"
                    parsed_rules.add(
                        FirewallRule(
                            source=normalized_source,
                            port=port,
                            protocol=normalized_protocol,
                        )
                    )

        return tuple(sorted(parsed_rules, key=lambda item: (item.source, item.port, item.protocol)))

    def _desired_default_incoming_policy(self) -> str | None:
        desired = self.config.get("desired_state", {})
        if not isinstance(desired, dict):
            return None
        raw = desired.get("default_incoming_policy")
        if not isinstance(raw, str):
            return None
        lowered = raw.strip().lower()
        if lowered in {"deny", "allow"}:
            return lowered
        return None

    async def _publish_drift_alert(
        self,
        *,
        backend_name: str,
        missing_rules: list[FirewallRule],
        unexpected_rules: list[FirewallRule],
        live_policy: str | None,
        desired_policy: str | None,
        enforce: bool,
    ) -> None:
        await self.ctx.event_bus.publish(
            "alert.firewall.drift_detected",
            {
                "backend": backend_name,
                "missing_rules": [_rule_to_dict(rule) for rule in missing_rules],
                "unexpected_rules": [_rule_to_dict(rule) for rule in unexpected_rules],
                "live_default_incoming_policy": live_policy,
                "desired_default_incoming_policy": desired_policy,
                "enforce": enforce,
            },
        )

    async def _record(self, result: ToolResult) -> None:
        await self.ctx.audit.append(
            action_type="tool_run",
            source="scheduler",
            description=result.summary,
            outcome=result.outcome.value,
            details=result.details,
        )


def _build_summary(
    *,
    drift_detected: bool,
    enforce: bool,
    missing_count: int,
    unexpected_count: int,
) -> str:
    if not drift_detected:
        return "Firewall state matches desired configuration."
    if enforce:
        return (
            "Firewall reconciled to desired configuration "
            f"(added={missing_count}, removed={unexpected_count})."
        )
    return f"Firewall drift detected (missing={missing_count}, unexpected={unexpected_count})."


def _state_to_dict(state: FirewallState) -> dict[str, Any]:
    return {
        "backend": state.backend,
        "default_incoming_policy": state.default_incoming_policy,
        "allow_rules": [_rule_to_dict(rule) for rule in state.allow_rules],
        "raw_output": state.raw_output[:4000],
    }


def _rule_to_dict(rule: FirewallRule) -> dict[str, Any]:
    return asdict(rule)


def _calculate_rule_drift(
    *,
    live: tuple[FirewallRule, ...],
    desired: tuple[FirewallRule, ...],
) -> tuple[list[FirewallRule], list[FirewallRule]]:
    live_set = set(live)
    desired_set = set(desired)
    missing = sorted(
        desired_set - live_set, key=lambda item: (item.source, item.port, item.protocol)
    )
    unexpected = sorted(
        live_set - desired_set, key=lambda item: (item.source, item.port, item.protocol)
    )
    return missing, unexpected


def _policy_drift(*, live_policy: str | None, desired_policy: str | None) -> bool:
    if desired_policy is None:
        return False
    if live_policy is None:
        return True
    return live_policy.strip().lower() != desired_policy.strip().lower()


def _cron_from_interval_seconds(interval_seconds: float) -> str:
    minutes = max(1, int(interval_seconds // 60))
    if interval_seconds % 60 != 0:
        minutes += 1
    if minutes < 60:
        return f"*/{minutes} * * * *"
    if minutes % 60 == 0:
        hours = minutes // 60
        if hours < 24:
            return f"0 */{hours} * * *"
    if minutes % 1440 == 0:
        days = minutes // 1440
        if days < 31:
            return f"0 0 */{days} * *"
    return f"*/{minutes} * * * *"
