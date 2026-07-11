"""Rule Engine service: in-memory Sigma Rule management and log evaluation."""

import datetime
import logging
import re
import uuid
from typing import Any, Callable

from src.exceptions import RuleEngineError
from src.models import Alert, SigmaRule
from src.rule_engine.evaluator import _match_selection, evaluate
from src.rule_engine.window import SlidingWindow

logger = logging.getLogger(__name__)

_TIMEFRAME_RE = re.compile(r"^(\d+)([smh])$")
_TIMEFRAME_UNITS: dict[str, int] = {"s": 1, "m": 60, "h": 3600}
_AGG_CONDITION_RE = re.compile(
    r"^(\w+)\s*\|\s*count\(\)\s*by\s*(\w+)\s*>\s*(\d+)$"
)


def _build_rule(payload: dict[str, Any], *, source: str = "rule payload") -> SigmaRule:
    """Construct a SigmaRule from a rule payload dict.

    Args:
        payload: Dict with ``id``, ``title``, ``level``, ``detection`` keys.
        source: Human-readable origin description, used in error messages.

    Raises:
        RuleEngineError: If the payload is None, not a dict, or missing a required field.
    """
    if not isinstance(payload, dict):
        raise RuleEngineError(
            f"{source} must be a JSON object, got {type(payload).__name__}"
        )
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

    Time-window aggregation rules (those with a ``timeframe`` key in their
    detection block) are evaluated using an in-memory sliding window per host
    per rule (ADR-0010). The window state is keyed by rule_id and host.

    Args:
        rules: Initial Sigma Rules loaded at startup.  Copied internally so the
               caller's list is not mutated.
        clock: Clock function for the sliding windows. Defaults to
               ``time.monotonic``. Inject a controlled clock in tests.
    """

    def __init__(
        self,
        rules: list[SigmaRule] | None = None,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._rules: list[SigmaRule] = list(rules) if rules else []
        self._clock = clock
        self._windows: dict[str, SlidingWindow] = {}

    @property
    def rule_count(self) -> int:
        """Number of Sigma Rules currently loaded."""
        return len(self._rules)

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
            rule = _build_rule(rule_payload)
            self._rules.append(rule)
            return rule

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
            if not isinstance(rule_payload, dict):
                raise RuleEngineError(
                    f"Rule update envelope 'rule' field must be a JSON object, got {type(rule_payload).__name__}"
                )
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
            self._windows.pop(rule_id, None)
            return None

        raise RuleEngineError(f"Unrecognised rule update op: {op!r}")

    def _get_window(self, rule_id: str) -> SlidingWindow:
        if rule_id not in self._windows:
            self._windows[rule_id] = SlidingWindow(now=self._clock)
        return self._windows[rule_id]

    def _evaluate_aggregation(self, rule: SigmaRule, raw_log: dict[str, Any]) -> Alert | None:
        """Evaluate one aggregation rule against raw_log using the sliding window.

        Returns an Alert if the selection matches and the per-host event count
        within the timeframe exceeds the rule's threshold; None otherwise.

        Raises:
            RuleEngineError: If the condition or timeframe cannot be parsed.
        """
        condition = str(rule.detection.get("condition", ""))
        timeframe_str = str(rule.detection.get("timeframe", ""))

        m = _AGG_CONDITION_RE.match(condition.strip())
        if not m:
            raise RuleEngineError(
                f"Rule {rule.id!r}: unsupported aggregation condition {condition!r}; "
                "expected 'selection | count() by <field> > <N>'"
            )
        selection_name = m.group(1)
        threshold = int(m.group(3))

        tf_m = _TIMEFRAME_RE.match(timeframe_str.strip())
        if not tf_m:
            raise RuleEngineError(
                f"Rule {rule.id!r}: invalid timeframe {timeframe_str!r}; "
                "expected '<N>s', '<N>m', or '<N>h'"
            )
        window_seconds = float(tf_m.group(1)) * _TIMEFRAME_UNITS[tf_m.group(2)]

        groups = {k: v for k, v in rule.detection.items() if k not in ("condition", "timeframe")}
        if selection_name not in groups:
            raise RuleEngineError(
                f"Rule {rule.id!r}: unknown selection group {selection_name!r}"
            )

        if not _match_selection(raw_log, groups[selection_name]):
            return None

        host = str(raw_log.get("host", ""))
        window = self._get_window(rule.id)
        window.add(host)
        if window.count(host, window_seconds) > threshold:
            return Alert(
                alert_id=str(uuid.uuid4()),
                rule_id=rule.id,
                rule_title=rule.title,
                severity=rule.level,
                matched_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                host=host,
                raw_log=raw_log,
            )
        return None

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
        regular: list[SigmaRule] = []
        alerts: list[Alert] = []

        for rule in rules_snapshot:
            if "timeframe" in rule.detection:
                alert = self._evaluate_aggregation(rule, raw_log)
                if alert is not None:
                    alerts.append(alert)
            else:
                regular.append(rule)

        alerts.extend(evaluate(raw_log, regular))
        return alerts
