from __future__ import annotations

import io

from system_sentinel.setup.wizard import (
    SetupWizard,
    StepOutcome,
    WizardContext,
    WizardStep,
    WizardStepResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_step(
    name: str = "step_a",
    description: str = "Do something",
    outcome: StepOutcome = StepOutcome.SUCCESS,
    message: str = "ok",
    error: str | None = None,
    check_safe: bool = False,
) -> WizardStep:
    """Build a WizardStep whose runner always returns the given outcome."""

    def runner(_ctx: WizardContext) -> WizardStepResult:
        return WizardStepResult(
            step_name=name,
            outcome=outcome,
            message=message,
            error=error,
        )

    return WizardStep(
        name=name,
        description=description,
        runner=runner,
        check_safe=check_safe,
    )


def _make_wizard(*steps: WizardStep) -> tuple[SetupWizard, io.StringIO]:
    buf = io.StringIO()
    wizard = SetupWizard(steps=list(steps), output=buf)
    return wizard, buf


# ---------------------------------------------------------------------------
# WizardStepResult
# ---------------------------------------------------------------------------


class TestWizardStepResult:
    def test_success_result_has_no_error_by_default(self) -> None:
        r = WizardStepResult(step_name="x", outcome=StepOutcome.SUCCESS, message="done")
        assert r.error is None

    def test_failure_result_carries_error_string(self) -> None:
        r = WizardStepResult(
            step_name="x",
            outcome=StepOutcome.FAILURE,
            message="failed",
            error="command not found: apt",
        )
        assert r.error == "command not found: apt"

    def test_step_outcome_is_comparable_to_string(self) -> None:
        assert StepOutcome.SUCCESS == "success"
        assert StepOutcome.FAILURE == "failure"
        assert StepOutcome.SKIPPED == "skipped"


# ---------------------------------------------------------------------------
# WizardContext
# ---------------------------------------------------------------------------


class TestWizardContext:
    def test_default_context_is_interactive_and_non_check(self) -> None:
        ctx = WizardContext()
        assert ctx.check_only is False
        assert ctx.unattended is False
        assert ctx.enabled_features == []

    def test_enabled_features_are_independent_across_instances(self) -> None:
        ctx_a = WizardContext()
        ctx_b = WizardContext()
        ctx_a.enabled_features.append("gpu")
        assert ctx_b.enabled_features == [], "Mutable default must not be shared between instances"


# ---------------------------------------------------------------------------
# WizardStep
# ---------------------------------------------------------------------------


class TestWizardStep:
    def test_check_safe_defaults_to_false(self) -> None:
        step = _make_step()
        assert step.check_safe is False

    def test_check_safe_can_be_set_to_true(self) -> None:
        step = _make_step(check_safe=True)
        assert step.check_safe is True


# ---------------------------------------------------------------------------
# SetupWizard.run — normal execution
# ---------------------------------------------------------------------------


class TestSetupWizardRun:
    def test_empty_step_list_returns_empty_results(self) -> None:
        wizard, _ = _make_wizard()
        results = wizard.run(WizardContext())
        assert results == []

    def test_single_success_step_returns_one_result(self) -> None:
        wizard, _ = _make_wizard(_make_step(name="s1", outcome=StepOutcome.SUCCESS))
        results = wizard.run(WizardContext())
        assert len(results) == 1
        assert results[0].outcome == StepOutcome.SUCCESS

    def test_all_steps_run_when_all_succeed(self) -> None:
        steps = [
            _make_step(name="s1", outcome=StepOutcome.SUCCESS),
            _make_step(name="s2", outcome=StepOutcome.SUCCESS),
            _make_step(name="s3", outcome=StepOutcome.SUCCESS),
        ]
        wizard, _ = _make_wizard(*steps)
        results = wizard.run(WizardContext())
        assert len(results) == 3

    def test_run_stops_after_first_failure(self) -> None:
        steps = [
            _make_step(name="ok_before", outcome=StepOutcome.SUCCESS),
            _make_step(name="fail_here", outcome=StepOutcome.FAILURE),
            _make_step(name="never_runs", outcome=StepOutcome.SUCCESS),
        ]
        wizard, _ = _make_wizard(*steps)
        results = wizard.run(WizardContext())
        assert len(results) == 2
        assert results[-1].step_name == "fail_here"

    def test_run_halts_on_first_step_failure(self) -> None:
        steps = [
            _make_step(name="instant_fail", outcome=StepOutcome.FAILURE),
            _make_step(name="unreachable", outcome=StepOutcome.SUCCESS),
        ]
        wizard, _ = _make_wizard(*steps)
        results = wizard.run(WizardContext())
        assert len(results) == 1

    def test_step_results_preserve_order(self) -> None:
        names = ["alpha", "beta", "gamma"]
        steps = [_make_step(name=n, outcome=StepOutcome.SUCCESS) for n in names]
        wizard, _ = _make_wizard(*steps)
        results = wizard.run(WizardContext())
        assert [r.step_name for r in results] == names

    def test_step_runner_receives_context(self) -> None:
        received: list[WizardContext] = []

        def capturing_runner(ctx: WizardContext) -> WizardStepResult:
            received.append(ctx)
            return WizardStepResult(step_name="capture", outcome=StepOutcome.SUCCESS, message="ok")

        step = WizardStep(
            name="capture",
            description="Capture context",
            runner=capturing_runner,
            check_safe=True,
        )
        wizard, _ = _make_wizard(step)
        ctx = WizardContext(unattended=True)
        wizard.run(ctx)
        assert len(received) == 1
        assert received[0] is ctx


# ---------------------------------------------------------------------------
# SetupWizard.run — check_only mode
# ---------------------------------------------------------------------------


class TestSetupWizardCheckOnly:
    def test_non_check_safe_step_is_skipped_in_check_only_mode(self) -> None:
        step = _make_step(name="writes_to_disk", check_safe=False)
        wizard, _ = _make_wizard(step)
        results = wizard.run(WizardContext(check_only=True))
        assert len(results) == 1
        assert results[0].outcome == StepOutcome.SKIPPED

    def test_check_safe_step_runs_in_check_only_mode(self) -> None:
        step = _make_step(name="read_only_check", check_safe=True, outcome=StepOutcome.SUCCESS)
        wizard, _ = _make_wizard(step)
        results = wizard.run(WizardContext(check_only=True))
        assert results[0].outcome == StepOutcome.SUCCESS

    def test_mixed_steps_in_check_only_mode(self) -> None:
        steps = [
            _make_step(name="safe", check_safe=True, outcome=StepOutcome.SUCCESS),
            _make_step(name="unsafe", check_safe=False, outcome=StepOutcome.SUCCESS),
            _make_step(name="safe2", check_safe=True, outcome=StepOutcome.SUCCESS),
        ]
        wizard, _ = _make_wizard(*steps)
        results = wizard.run(WizardContext(check_only=True))
        assert results[0].outcome == StepOutcome.SUCCESS  # safe: ran
        assert results[1].outcome == StepOutcome.SKIPPED  # unsafe: skipped
        assert results[2].outcome == StepOutcome.SUCCESS  # safe: ran

    def test_skipped_step_does_not_halt_execution(self) -> None:
        steps = [
            _make_step(name="skip_me", check_safe=False),
            _make_step(name="run_me", check_safe=True, outcome=StepOutcome.SUCCESS),
        ]
        wizard, _ = _make_wizard(*steps)
        results = wizard.run(WizardContext(check_only=True))
        assert len(results) == 2
        assert results[1].outcome == StepOutcome.SUCCESS

    def test_check_only_failure_still_halts_execution(self) -> None:
        steps = [
            _make_step(name="safe_fail", check_safe=True, outcome=StepOutcome.FAILURE),
            _make_step(name="unreachable", check_safe=True, outcome=StepOutcome.SUCCESS),
        ]
        wizard, _ = _make_wizard(*steps)
        results = wizard.run(WizardContext(check_only=True))
        assert len(results) == 1
        assert results[0].outcome == StepOutcome.FAILURE


# ---------------------------------------------------------------------------
# SetupWizard.succeeded
# ---------------------------------------------------------------------------


class TestSetupWizardSucceeded:
    def test_empty_results_is_success(self) -> None:
        assert SetupWizard.succeeded([]) is True

    def test_all_success_results_is_success(self) -> None:
        results = [
            WizardStepResult("s1", StepOutcome.SUCCESS, "ok"),
            WizardStepResult("s2", StepOutcome.SUCCESS, "ok"),
        ]
        assert SetupWizard.succeeded(results) is True

    def test_skipped_results_count_as_success(self) -> None:
        results = [
            WizardStepResult("s1", StepOutcome.SUCCESS, "ok"),
            WizardStepResult("s2", StepOutcome.SKIPPED, "skipped"),
        ]
        assert SetupWizard.succeeded(results) is True

    def test_any_failure_returns_false(self) -> None:
        results = [
            WizardStepResult("s1", StepOutcome.SUCCESS, "ok"),
            WizardStepResult("s2", StepOutcome.FAILURE, "failed"),
        ]
        assert SetupWizard.succeeded(results) is False

    def test_single_failure_returns_false(self) -> None:
        results = [WizardStepResult("s1", StepOutcome.FAILURE, "failed")]
        assert SetupWizard.succeeded(results) is False

    def test_succeeded_callable_on_class_without_instance(self) -> None:
        assert SetupWizard.succeeded([]) is True


# ---------------------------------------------------------------------------
# SetupWizard output
# ---------------------------------------------------------------------------


class TestSetupWizardOutput:
    def test_success_icon_appears_in_output(self) -> None:
        wizard, buf = _make_wizard(
            _make_step(name="my_step", outcome=StepOutcome.SUCCESS, message="all good")
        )
        wizard.run(WizardContext())
        assert "✓" in buf.getvalue()

    def test_failure_icon_appears_in_output(self) -> None:
        wizard, buf = _make_wizard(
            _make_step(name="my_step", outcome=StepOutcome.FAILURE, message="broke")
        )
        wizard.run(WizardContext())
        assert "✗" in buf.getvalue()

    def test_skipped_icon_appears_in_output_for_check_only(self) -> None:
        wizard, buf = _make_wizard(_make_step(name="s", check_safe=False))
        wizard.run(WizardContext(check_only=True))
        assert "-" in buf.getvalue()

    def test_step_name_appears_in_output(self) -> None:
        wizard, buf = _make_wizard(
            _make_step(name="unique_step_name", outcome=StepOutcome.SUCCESS, message="done")
        )
        wizard.run(WizardContext())
        assert "unique_step_name" in buf.getvalue()

    def test_error_string_appears_in_output_on_failure(self) -> None:
        wizard, buf = _make_wizard(
            _make_step(
                name="bad",
                outcome=StepOutcome.FAILURE,
                message="failed",
                error="disk full",
            )
        )
        wizard.run(WizardContext())
        assert "disk full" in buf.getvalue()

    def test_halt_message_appears_after_failure(self) -> None:
        wizard, buf = _make_wizard(_make_step(name="bad", outcome=StepOutcome.FAILURE))
        wizard.run(WizardContext())
        assert "sentinel setup" in buf.getvalue()

    def test_no_output_for_empty_step_list(self) -> None:
        wizard, buf = _make_wizard()
        wizard.run(WizardContext())
        assert buf.getvalue() == ""
