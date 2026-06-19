"""Sigma Rule evaluator for the Kafka Sigma Engine."""

import datetime
import uuid
from typing import Any

from src.exceptions import RuleEngineError
from src.models import Alert, SigmaRule


def _match_field(log_value: Any, rule_value: Any, modifier: str | None) -> bool:
    """Check if a single log field value satisfies the rule's condition.

    A list rule_value is OR — the log value must satisfy at least one element.
    Values are compared as strings to handle YAML string vs. integer mismatches.
    """
    if isinstance(rule_value, list):
        return any(_match_field(log_value, v, modifier) for v in rule_value)

    lv = str(log_value)
    rv = str(rule_value)

    if modifier is None:
        return lv == rv
    elif modifier == "contains":
        return rv in lv
    elif modifier == "startswith":
        return lv.startswith(rv)
    elif modifier == "endswith":
        return lv.endswith(rv)
    return False


def _match_selection(raw_log: dict[str, Any], selection: dict[str, Any]) -> bool:
    """Return True iff raw_log satisfies every field condition in selection (AND logic)."""
    for key, expected in selection.items():
        if "|" in key:
            field_name, modifier = key.split("|", 1)
        else:
            field_name, modifier = key, None

        if field_name not in raw_log:
            return False
        if not _match_field(raw_log[field_name], expected, modifier):
            return False

    return True


class _ConditionParser:
    """Recursive-descent parser for Level 2 Sigma condition strings.

    Grammar (lowest → highest precedence):
        expr   ::= and_expr ("or" and_expr)*
        and_expr ::= not_expr ("and" not_expr)*
        not_expr ::= "not" not_expr | primary
        primary  ::= "(" expr ")" | NAME
    """

    def __init__(
        self,
        tokens: list[str],
        groups: dict[str, dict[str, Any]],
        raw_log: dict[str, Any],
    ) -> None:
        self._tokens = tokens
        self._pos = 0
        self._groups = groups
        self._raw_log = raw_log

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _consume(self) -> str:
        token = self._tokens[self._pos]
        self._pos += 1
        return token

    def parse(self) -> bool:
        return self._or_expr()

    def _or_expr(self) -> bool:
        result = self._and_expr()
        while self._peek() == "or":
            self._consume()
            rhs = self._and_expr()  # always advance _pos before combining
            result = result or rhs
        return result

    def _and_expr(self) -> bool:
        result = self._not_expr()
        while self._peek() == "and":
            self._consume()
            rhs = self._not_expr()  # always advance _pos before combining
            result = result and rhs
        return result

    def _not_expr(self) -> bool:
        if self._peek() == "not":
            self._consume()
            return not self._not_expr()
        return self._primary()

    def _primary(self) -> bool:
        token = self._consume()
        if token == "(":
            result = self._or_expr()
            self._consume()
            return result
        if token not in self._groups:
            raise RuleEngineError(f"Unknown selection group in condition: {token!r}")
        return _match_selection(self._raw_log, self._groups[token])


def evaluate(raw_log: dict[str, Any], rules: list[SigmaRule]) -> list[Alert]:
    """Evaluate a Raw Log against all Sigma Rules and return matching Alerts.

    Args:
        raw_log: The raw security event to evaluate.
        rules: Loaded Sigma Rules to match against.

    Returns:
        One Alert per matching rule, in rule-list order.
    """
    alerts: list[Alert] = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for rule in rules:
        condition = str(rule.detection.get("condition", ""))
        groups: dict[str, dict[str, Any]] = {
            k: v for k, v in rule.detection.items() if k != "condition"
        }
        tokens = condition.split()
        if _ConditionParser(tokens, groups, raw_log).parse():
            alerts.append(
                Alert(
                    alert_id=str(uuid.uuid4()),
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.level,
                    matched_at=now,
                    host=str(raw_log.get("host", "")),
                    raw_log=raw_log,
                )
            )

    return alerts
