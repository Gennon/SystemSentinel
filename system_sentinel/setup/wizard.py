from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import sys
from typing import IO, ClassVar


class StepOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"


@dataclass
class WizardStepResult:
    step_name: str
    outcome: StepOutcome
    message: str
    error: str | None = None


@dataclass
class WizardContext:
    check_only: bool = False
    unattended: bool = False
    enabled_features: list[str] = field(default_factory=list)


StepRunner = Callable[[WizardContext], WizardStepResult]


@dataclass
class WizardStep:
    name: str
    description: str
    runner: StepRunner
    check_safe: bool = False


class SetupWizard:
    """Orchestrates an ordered sequence of WizardStep objects.

    Steps are executed in declaration order. If any step returns
    StepOutcome.FAILURE, execution halts immediately and the partial
    results list is returned.

    In check_only mode (ctx.check_only is True), only steps whose
    check_safe attribute is True are executed; all others are
    recorded as StepOutcome.SKIPPED.
    """

    STEP_ICON: ClassVar[dict[StepOutcome, str]] = {
        StepOutcome.SUCCESS: "✓",
        StepOutcome.FAILURE: "✗",
        StepOutcome.SKIPPED: "-",
    }

    def __init__(
        self,
        steps: list[WizardStep],
        output: IO[str] = sys.stdout,
    ) -> None:
        self._steps = steps
        self._output = output

    def run(self, ctx: WizardContext) -> list[WizardStepResult]:
        """Execute all steps and return the collected results.

        Stops after the first FAILURE.
        """
        results: list[WizardStepResult] = []

        for step in self._steps:
            if ctx.check_only and not step.check_safe:
                result = WizardStepResult(
                    step_name=step.name,
                    outcome=StepOutcome.SKIPPED,
                    message="Skipped in check-only mode.",
                )
            else:
                self._output.write(f"  Running: {step.description} ...\n")
                result = step.runner(ctx)

            icon = self.STEP_ICON[result.outcome]
            self._output.write(f"  {icon} {step.name}: {result.message}\n")

            if result.error:
                self._output.write(f"    Error: {result.error}\n")

            results.append(result)

            if result.outcome == StepOutcome.FAILURE:
                self._output.write(
                    "\nSetup halted. Fix the error above and re-run `sentinel setup`.\n"
                )
                break

        return results

    @staticmethod
    def succeeded(results: list[WizardStepResult]) -> bool:
        """Return True if no result has outcome FAILURE."""
        return all(r.outcome != StepOutcome.FAILURE for r in results)
