"""Unit tests for the Rule Engine.

Tests observable behavior via public interfaces:
- evaluate(raw_log, rules) -> list[Alert]
- load_rules(path) -> list[SigmaRule]
"""

from pathlib import Path
from typing import Any

import pytest

from src.exceptions import RuleEngineError
from src.models import SigmaRule
from src.rule_engine.evaluator import evaluate
from src.rule_engine.loader import load_rules


def _make_rule(
    rule_id: str = "rule-001",
    title: str = "Test Rule",
    level: str = "medium",
    detection: dict[str, Any] | None = None,
) -> SigmaRule:
    if detection is None:
        detection = {
            "selection": {"log_type": "windows_event", "event_id": "4625"},
            "condition": "selection",
        }
    return SigmaRule(id=rule_id, title=title, level=level, detection=detection)


# ---------------------------------------------------------------------------
# evaluate() — basic matching
# ---------------------------------------------------------------------------


def test_evaluate_matching_log_returns_one_alert() -> None:
    rule = _make_rule()
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event", "event_id": "4625"}
    alerts = evaluate(raw_log, [rule])
    assert len(alerts) == 1


def test_evaluate_alert_has_correct_fields() -> None:
    rule = _make_rule(rule_id="win-001", title="Windows Login", level="high")
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event", "event_id": "4625"}
    alerts = evaluate(raw_log, [rule])
    alert = alerts[0]
    assert alert.rule_id == "win-001"
    assert alert.rule_title == "Windows Login"
    assert alert.severity == "high"
    assert alert.host == "web-01"
    assert alert.raw_log == raw_log
    assert alert.alert_id  # non-empty UUID string


def test_evaluate_non_matching_log_returns_empty() -> None:
    rule = _make_rule()
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "cloudtrail", "action": "GetObject"}
    assert evaluate(raw_log, [rule]) == []


def test_evaluate_no_rules_returns_empty() -> None:
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event"}
    assert evaluate(raw_log, []) == []


def test_evaluate_multiple_rules_all_match_returns_multiple_alerts() -> None:
    rule1 = _make_rule(rule_id="rule-001")
    rule2 = _make_rule(rule_id="rule-002")
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event", "event_id": "4625"}
    alerts = evaluate(raw_log, [rule1, rule2])
    assert len(alerts) == 2
    assert {a.rule_id for a in alerts} == {"rule-001", "rule-002"}


def test_evaluate_multiple_rules_partial_match() -> None:
    rule1 = _make_rule(rule_id="rule-001")
    rule2 = _make_rule(
        rule_id="rule-002",
        detection={"sel": {"log_type": "cloudtrail"}, "condition": "sel"},
    )
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event", "event_id": "4625"}
    alerts = evaluate(raw_log, [rule1, rule2])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "rule-001"


def test_evaluate_missing_field_does_not_match() -> None:
    rule = _make_rule()
    # Raw log is missing event_id
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event"}
    assert evaluate(raw_log, [rule]) == []


def test_evaluate_integer_field_matches_string_rule_value() -> None:
    """Raw logs may carry integer event_ids; rule values are YAML strings."""
    rule = _make_rule()
    raw_log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event", "event_id": 4625}
    assert len(evaluate(raw_log, [rule])) == 1


# ---------------------------------------------------------------------------
# evaluate() — string modifiers
# ---------------------------------------------------------------------------


def test_evaluate_startswith_modifier_matches() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="high",
        detection={"sel": {"action|startswith": "Delete"}, "condition": "sel"},
    )
    assert len(evaluate({"host": "h", "action": "DeleteBucket"}, [rule])) == 1


def test_evaluate_startswith_modifier_no_match() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="high",
        detection={"sel": {"action|startswith": "Delete"}, "condition": "sel"},
    )
    assert evaluate({"host": "h", "action": "GetObject"}, [rule]) == []


def test_evaluate_contains_modifier_matches() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="medium",
        detection={"sel": {"process_name|contains": "powershell"}, "condition": "sel"},
    )
    assert len(evaluate({"host": "h", "process_name": "powershell.exe"}, [rule])) == 1


def test_evaluate_contains_modifier_no_match() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="medium",
        detection={"sel": {"process_name|contains": "powershell"}, "condition": "sel"},
    )
    assert evaluate({"host": "h", "process_name": "cmd.exe"}, [rule]) == []


def test_evaluate_endswith_modifier_matches() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="low",
        detection={"sel": {"process_name|endswith": ".exe"}, "condition": "sel"},
    )
    assert len(evaluate({"host": "h", "process_name": "cmd.exe"}, [rule])) == 1


def test_evaluate_endswith_modifier_no_match() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="low",
        detection={"sel": {"process_name|endswith": ".exe"}, "condition": "sel"},
    )
    assert evaluate({"host": "h", "process_name": "bash"}, [rule]) == []


def test_evaluate_field_value_list_matches_any() -> None:
    """A list of values in a selection field is an OR — any value matches."""
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="medium",
        detection={"sel": {"event_id": ["4624", "4625", "4648"]}, "condition": "sel"},
    )
    assert len(evaluate({"host": "h", "event_id": "4625"}, [rule])) == 1
    assert evaluate({"host": "h", "event_id": "9999"}, [rule]) == []


# ---------------------------------------------------------------------------
# evaluate() — boolean logic
# ---------------------------------------------------------------------------


def test_evaluate_and_condition_requires_both_selections() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="high",
        detection={
            "sel1": {"log_type": "windows_event"},
            "sel2": {"event_id": "4625"},
            "condition": "sel1 and sel2",
        },
    )
    # Both present → match
    assert len(evaluate({"host": "h", "log_type": "windows_event", "event_id": "4625"}, [rule])) == 1
    # Only sel1 → no match
    assert evaluate({"host": "h", "log_type": "windows_event"}, [rule]) == []


def test_evaluate_or_condition_accepts_either_selection() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="medium",
        detection={
            "sel1": {"log_type": "windows_event"},
            "sel2": {"log_type": "cloudtrail"},
            "condition": "sel1 or sel2",
        },
    )
    assert len(evaluate({"host": "h", "log_type": "windows_event"}, [rule])) == 1
    assert len(evaluate({"host": "h", "log_type": "cloudtrail"}, [rule])) == 1
    assert evaluate({"host": "h", "log_type": "other"}, [rule]) == []


def test_evaluate_not_condition_suppresses_alert() -> None:
    rule = SigmaRule(
        id="r1",
        title="R1",
        level="medium",
        detection={
            "sel": {"log_type": "windows_event"},
            "filter": {"event_id": "4624"},
            "condition": "sel and not filter",
        },
    )
    # 4625 is a failed login → should match
    assert len(evaluate({"host": "h", "log_type": "windows_event", "event_id": "4625"}, [rule])) == 1
    # 4624 is a normal login → filtered out
    assert evaluate({"host": "h", "log_type": "windows_event", "event_id": "4624"}, [rule]) == []


# ---------------------------------------------------------------------------
# load_rules()
# ---------------------------------------------------------------------------

_RULE_YAML = """\
id: test-{n}
title: Test Rule {n}
level: medium
detection:
  selection:
    log_type: windows_event
  condition: selection
"""


def test_load_rules_returns_all_yaml_files(tmp_path: Path) -> None:
    (tmp_path / "rule1.yml").write_text(_RULE_YAML.format(n=1))
    (tmp_path / "rule2.yml").write_text(_RULE_YAML.format(n=2))
    rules = load_rules(tmp_path)
    assert len(rules) == 2
    assert {r.id for r in rules} == {"test-1", "test-2"}


def test_load_rules_returns_sigma_rule_objects(tmp_path: Path) -> None:
    yaml_text = """\
id: aws-delete-001
title: AWS S3 Deletion
level: high
detection:
  selection:
    log_type: cloudtrail
    action|startswith: Delete
  condition: selection
"""
    (tmp_path / "rule.yml").write_text(yaml_text)
    rules = load_rules(tmp_path)
    assert len(rules) == 1
    rule = rules[0]
    assert isinstance(rule, SigmaRule)
    assert rule.id == "aws-delete-001"
    assert rule.level == "high"
    assert rule.detection["condition"] == "selection"


def test_load_rules_empty_directory_returns_empty(tmp_path: Path) -> None:
    assert load_rules(tmp_path) == []


def test_load_rules_missing_required_field_raises(tmp_path: Path) -> None:
    bad_yaml = "id: test-001\ntitle: Incomplete Rule\n"
    (tmp_path / "bad.yml").write_text(bad_yaml)
    with pytest.raises(RuleEngineError):
        load_rules(tmp_path)


def test_load_rules_integrates_with_evaluate(tmp_path: Path) -> None:
    """End-to-end: load rules from YAML and evaluate a raw log."""
    yaml_text = """\
id: win-failed-login-001
title: Windows Failed Login Attempt
level: medium
detection:
  selection:
    log_type: windows_event
    event_id: '4625'
  condition: selection
"""
    (tmp_path / "rule.yml").write_text(yaml_text)
    rules = load_rules(tmp_path)

    matching_log: dict[str, Any] = {"host": "db-01", "log_type": "windows_event", "event_id": "4625"}
    non_matching_log: dict[str, Any] = {"host": "db-01", "log_type": "cloudtrail", "action": "GetObject"}

    alerts = evaluate(matching_log, rules)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-failed-login-001"
    assert alerts[0].host == "db-01"

    assert evaluate(non_matching_log, rules) == []
