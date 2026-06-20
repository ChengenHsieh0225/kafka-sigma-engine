"""Rule Engine service: in-memory Sigma Rule management and log evaluation."""

import logging
from typing import Any

from src.exceptions import RuleEngineError
from src.models import Alert, SigmaRule
from src.rule_engine.evaluator import evaluate

logger = logging.getLogger(__name__)


def _build_rule(payload: dict[str, Any], *, source: str = "rule payload") -> SigmaRule:
    """Construct a SigmaRule from a rule payload dict.

    Args:
        payload: Dict with ``id``, ``title``, ``level``, ``detection`` keys.
        source: Human-readable origin description, used in error messages.

    Raises:
        RuleEngineError: If the payload is missing a required field.
    """
    try:
        return SigmaRule(
            id=payload["id"],
            title=payload["title"],
            level=payload["level"],
            detection=payload["detection"],
        )
    except KeyError as exc:
        raise RuleEngineError(
            f"Missing required field {exc} in {source}"
        ) from exc


class RuleEngineService:
    """Holds the active Sigma Rule set and evaluates Raw Logs in memory.

    Rules can be added, updated, or deleted at runtime without restart via
    the typed JSON envelope format on the rule-updates Kafka topic (ADR-0011).
    Legacy add-only hot_reload() is retained for backward compatibility.

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
        """Append a new Sigma Rule from a bare rule payload (add-only, PRD US 10).

        Args:
            payload: Dict with ``id``, ``title``, ``level``, ``detection`` keys.

        Returns:
            The newly appended SigmaRule.

        Raises:
            RuleEngineError: If the payload is missing a required field.
        """
        rule = _build_rule(payload)
        self._rules.append(rule)
        return rule

    def apply_rule_update(self, envelope: dict[str, Any]) -> SigmaRule | None:
        """Apply a typed rule lifecycle operation from the rule-updates Kafka topic.

        Envelope format (ADR-0011):
            ``{"op": "add", "rule": {...}}``
            ``{"op": "update"|"delete", "rule_id": "...", "rule": {...}}``

        ``rule_id`` is required for ``update`` and ``delete`` but optional for ``add``
        (the rule's own ``id`` field serves as the identifier). The ``rule`` field is
        omitted for ``delete``. Update and delete use snapshot semantics: ``self._rules``
        is rebound to a new list so any in-flight evaluation snapshot is not affected
        (ADR-0011).

        Args:
            envelope: Decoded JSON dict from the ``rule-updates`` topic.

        Returns:
            The new or updated SigmaRule for ``add``/``update``; ``None`` for ``delete``.

        Raises:
            RuleEngineError: If the envelope is malformed or ``op`` is unrecognised.
        """
        try:
            op: str = envelope["op"]
        except KeyError as exc:
            raise RuleEngineError(
                f"Rule update envelope missing required field: {exc}"
            ) from exc

        if op == "add":
            rule_payload = envelope.get("rule")
            if rule_payload is None:
                raise RuleEngineError("Rule update envelope missing 'rule' field for op='add'")
            return self.hot_reload(rule_payload)

        try:
            rule_id: str = envelope["rule_id"]
        except KeyError as exc:
            raise RuleEngineError(
                f"Rule update envelope missing required field: {exc}"
            ) from exc

        if op == "update":
            rule_payload = envelope.get("rule")
            if rule_payload is None:
                raise RuleEngineError("Rule update envelope missing 'rule' field for op='update'")
            if rule_payload.get("id") != rule_id:
                raise RuleEngineError(
                    f"Rule update envelope rule_id {rule_id!r} does not match "
                    f"rule payload id {rule_payload.get('id')!r}"
                )
            rule = _build_rule(rule_payload)
            replaced = False
            new_rules = []
            for r in self._rules:
                if r.id == rule_id:
                    new_rules.append(rule)
                    replaced = True
                else:
                    new_rules.append(r)
            if not replaced:
                logger.warning(
                    "op='update' did not find rule_id=%r; inserting as new rule", rule_id
                )
                new_rules.append(rule)
            self._rules = new_rules
            return rule

        if op == "delete":
            self._rules = [r for r in self._rules if r.id != rule_id]
            return None

        raise RuleEngineError(f"Unrecognised rule update op: {op!r}")

    def evaluate_log(self, raw_log: dict[str, Any]) -> list[Alert]:
        """Evaluate a Raw Log against all loaded Sigma Rules.

        Takes a snapshot of the current rule set so that a concurrent update or
        delete (ADR-0011) takes effect on the next log, not the current one.

        Args:
            raw_log: The raw security event to evaluate.

        Returns:
            One Alert per matching Sigma Rule.
        """
        rules_snapshot = self._rules
        return evaluate(raw_log, rules_snapshot)
