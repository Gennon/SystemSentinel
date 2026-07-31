"""Unit tests for ModelRouter (US-033)."""

from __future__ import annotations

from system_sentinel.llm.router import ModelRouter, RouteResult


class TestModelRouterDefaults:
    def test_no_rules_returns_default(self) -> None:
        router = ModelRouter(default_model="llama3.2", default_provider="ollama")
        result = router.resolve()
        assert result == RouteResult(model="llama3.2", provider="ollama", matched_rule=None)

    def test_no_rules_command_type_ignored(self) -> None:
        router = ModelRouter(default_model="llama3.2")
        result = router.resolve(command_type="ask")
        assert result.model == "llama3.2"
        assert result.matched_rule is None

    def test_default_provider_is_none_when_not_set(self) -> None:
        router = ModelRouter(default_model="llama3.2")
        assert router.default_provider is None


class TestModelRouterRuleMatching:
    def test_matches_command_type(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[{"command_type": "checkup", "model": "llama3.3"}],
        )
        result = router.resolve(command_type="checkup")
        assert result.model == "llama3.3"
        assert result.matched_rule is not None
        assert result.matched_rule["index"] == 0
        assert result.matched_rule["command_type"] == "checkup"

    def test_no_match_falls_through_to_default(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[{"command_type": "checkup", "model": "llama3.3"}],
        )
        result = router.resolve(command_type="ask")
        assert result.model == "llama3.2"
        assert result.matched_rule is None

    def test_matches_severity(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[
                {"command_type": "explain_alert", "severity": "critical", "model": "llama3.3:70b"}
            ],
        )
        result = router.resolve(command_type="explain_alert", severity="critical")
        assert result.model == "llama3.3:70b"
        assert result.matched_rule is not None

    def test_severity_must_also_match(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[
                {"command_type": "explain_alert", "severity": "critical", "model": "llama3.3:70b"}
            ],
        )
        result = router.resolve(command_type="explain_alert", severity="warning")
        assert result.model == "llama3.2"
        assert result.matched_rule is None

    def test_rule_with_no_severity_matches_any_severity(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[{"command_type": "explain_alert", "model": "llama3.3"}],
        )
        result = router.resolve(command_type="explain_alert", severity="critical")
        assert result.model == "llama3.3"

    def test_first_matching_rule_wins(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[
                {"command_type": "ask", "model": "first"},
                {"command_type": "ask", "model": "second"},
            ],
        )
        result = router.resolve(command_type="ask")
        assert result.model == "first"
        assert result.matched_rule["index"] == 0  # type: ignore[index]

    def test_provider_override_in_rule(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            default_provider="ollama",
            rules=[{"command_type": "ask", "provider": "openai", "model": "gpt-4o"}],
        )
        result = router.resolve(command_type="ask")
        assert result.provider == "openai"
        assert result.model == "gpt-4o"

    def test_rule_without_provider_keeps_none(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[{"command_type": "ask", "model": "big-model"}],
        )
        result = router.resolve(command_type="ask")
        assert result.provider is None

    def test_matched_rule_contains_metadata(self) -> None:
        router = ModelRouter(
            default_model="llama3.2",
            rules=[{"command_type": "checkup", "severity": "warning", "model": "llama3.3"}],
        )
        result = router.resolve(command_type="checkup", severity="warning")
        assert result.matched_rule == {
            "index": 0,
            "command_type": "checkup",
            "severity": "warning",
            "model": "llama3.3",
            "provider": None,
        }


class TestModelRouterFromConfig:
    def test_from_config_parses_model_and_provider(self) -> None:
        router = ModelRouter.from_config({"model": "llama3.2", "provider": "ollama"})
        assert router.default_model == "llama3.2"
        assert router.default_provider == "ollama"

    def test_from_config_parses_routing_rules(self) -> None:
        router = ModelRouter.from_config(
            {
                "model": "llama3.2",
                "provider": "ollama",
                "routing_rules": [
                    {"command_type": "checkup", "model": "llama3.3"},
                    {"command_type": "ask", "provider": "openai", "model": "gpt-4o"},
                ],
            }
        )
        result = router.resolve(command_type="checkup")
        assert result.model == "llama3.3"

        result2 = router.resolve(command_type="ask")
        assert result2.provider == "openai"
        assert result2.model == "gpt-4o"

    def test_from_config_handles_missing_keys(self) -> None:
        router = ModelRouter.from_config({})
        assert router.default_model == ""
        assert router.default_provider is None
        result = router.resolve(command_type="ask")
        assert result.matched_rule is None

    def test_from_config_ignores_non_dict_rules(self) -> None:
        router = ModelRouter.from_config(
            {"model": "x", "routing_rules": ["not-a-dict", {"command_type": "ask", "model": "y"}]}
        )
        result = router.resolve(command_type="ask")
        assert result.model == "y"
