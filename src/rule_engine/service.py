"""Rule Engine service: in-memory Sigma Rule management and log evaluation."""

from typing import Any

from src.exceptions import RuleEngineError
from src.models import Alert, SigmaRule
from src.rule_engine.evaluator import evaluate


class RuleEngineService:
    """Holds the active Sigma Rule set and evaluates Raw Logs in memory.

    Hot-reload is add-only (PRD US 10): new rules received via the rule-updates
    Kafka topic are appended to the active set; existing rules are never replaced
    or removed during a worker's lifetime.

    Args:
        rules: Initial Sigma Rules loaded at startup.  Copied internally so the
               caller's list is not mutated.
    """

    def __init__(self, rules: list[SigmaRule] | None = None) -> None:
        self._rules: list[SigmaRule] = list(rules) if rules else []

    @property
    def rule_count(self) -> int:
        """Number of Sigma Rules currently loaded."""
        return len(self._rules)

    def hot_reload(self, payload: dict[str, Any]) -> SigmaRule:
        """Append a new Sigma Rule from a decoded rule-updates Kafka message.

        Add-only: existing rules are never replaced or removed (PRD US 10).

        Args:
            payload: Decoded JSON dict from the ``rule-updates`` Kafka topic.

        Returns:
            The newly appended SigmaRule.

        Raises:
            RuleEngineError: If the payload is missing a required field.
        """
        try:
            rule = SigmaRule(
                id=payload["id"],
                title=payload["title"],
                level=payload["level"],
                detection=payload["detection"],
            )
        except KeyError as exc:
            raise RuleEngineError(
                f"Hot-reloaded rule payload is missing required field: {exc}"
            ) from exc
        self._rules.append(rule)
        return rule

    def evaluate_log(self, raw_log: dict[str, Any]) -> list[Alert]:
        """Evaluate a Raw Log against all loaded Sigma Rules.

        Args:
            raw_log: The raw security event to evaluate.

        Returns:
            One Alert per matching Sigma Rule.
        """
        return evaluate(raw_log, self._rules)
