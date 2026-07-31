"""Policy-based model routing for LLM requests.

Rules are evaluated top-to-bottom; the first matching rule wins.
If no rule matches, the default model/provider from ``llm.model`` /
``llm.provider`` is used.

Config example::

    llm:
      enabled: true
      provider: ollama
      model: llama3.2          # default fallback
      routing_rules:
        - command_type: explain_alert
          severity: critical
          model: llama3.3:70b
        - command_type: checkup
          model: llama3.3
        - command_type: ask
          provider: openai
          model: gpt-4o
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RouteResult:
    """The resolved routing decision for a single LLM call."""

    model: str
    """Model identifier to use (may be empty string → provider default)."""

    provider: str | None
    """Provider name override, or ``None`` to keep the active provider."""

    matched_rule: dict[str, Any] | None
    """Metadata of the matched routing rule, or ``None`` when the fallback was used."""


class ModelRouter:
    """Evaluates routing rules and returns a :class:`RouteResult`."""

    def __init__(
        self,
        default_model: str,
        default_provider: str | None = None,
        rules: list[dict[str, Any]] | None = None,
    ) -> None:
        self._default_model = default_model
        self._default_provider = default_provider
        self._rules: list[dict[str, Any]] = rules or []

    @property
    def default_model(self) -> str:
        return self._default_model

    @property
    def default_provider(self) -> str | None:
        return self._default_provider

    def resolve(
        self,
        command_type: str | None = None,
        severity: str | None = None,
    ) -> RouteResult:
        """Return the best matching route for *command_type* / *severity*.

        Iterates rules in declaration order; the first rule whose
        ``command_type`` and ``severity`` constraints are satisfied wins.
        A ``None`` constraint on a rule means *match anything*.
        """
        for index, rule in enumerate(self._rules):
            rule_command = rule.get("command_type")
            rule_severity = rule.get("severity")

            if rule_command is not None and rule_command != command_type:
                continue
            if rule_severity is not None and rule_severity != severity:
                continue

            model = str(rule.get("model") or self._default_model)
            raw_provider = rule.get("provider")
            provider = str(raw_provider) if raw_provider else None
            return RouteResult(
                model=model,
                provider=provider,
                matched_rule={
                    "index": index,
                    "command_type": rule_command,
                    "severity": rule_severity,
                    "model": model,
                    "provider": provider,
                },
            )

        return RouteResult(
            model=self._default_model,
            provider=self._default_provider,
            matched_rule=None,
        )

    @classmethod
    def from_config(cls, llm_config: dict[str, Any]) -> ModelRouter:
        """Build a :class:`ModelRouter` from the ``llm`` section of ``config.yaml``."""
        raw_model = llm_config.get("model")
        default_model = str(raw_model).strip() if isinstance(raw_model, str) else ""

        raw_provider = llm_config.get("provider")
        default_provider = str(raw_provider).strip() if isinstance(raw_provider, str) else None

        rules_raw = llm_config.get("routing_rules")
        rules: list[dict[str, Any]] = (
            [r for r in rules_raw if isinstance(r, dict)] if isinstance(rules_raw, list) else []
        )

        return cls(
            default_model=default_model,
            default_provider=default_provider,
            rules=rules,
        )
