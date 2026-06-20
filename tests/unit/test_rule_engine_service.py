"""Unit tests for RuleEngineService.

Tests observable behavior through the public interface:
- evaluate_log(raw_log) -> list[Alert]
- hot_reload(payload) -> SigmaRule (add-only per PRD US 10)
- rule_count property
"""

from typing import Any

import pytest

from src.exceptions import RuleEngineError
from src.models import SigmaRule
from src.rule_engine.service import RuleEngineService


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


def _make_payload(
    rule_id: str = "new-001",
    title: str = "New Rule",
    level: str = "medium",
    detection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if detection is None:
        detection = {
            "sel": {"log_type": "cloudtrail"},
            "condition": "sel",
        }
    return {"id": rule_id, "title": title, "level": level, "detection": detection}


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_service_starts_empty_with_no_rules() -> None:
    service = RuleEngineService()
    assert service.rule_count == 0


def test_service_initialises_with_provided_rules() -> None:
    rules = [_make_rule("r1"), _make_rule("r2")]
    service = RuleEngineService(rules)
    assert service.rule_count == 2


def test_service_does_not_mutate_callers_list() -> None:
    """RuleEngineService must copy the initial rule list, not hold a reference."""
    rules = [_make_rule()]
    service = RuleEngineService(rules)
    rules.clear()
    assert service.rule_count == 1


# ---------------------------------------------------------------------------
# evaluate_log()
# ---------------------------------------------------------------------------


def test_evaluate_log_returns_alert_for_matching_log() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    log: dict[str, Any] = {"host": "web-01", "log_type": "windows_event", "event_id": "4625"}
    alerts = service.evaluate_log(log)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-001"


def test_evaluate_log_returns_empty_for_non_matching_log() -> None:
    service = RuleEngineService([_make_rule()])
    assert service.evaluate_log({"host": "web-01", "log_type": "cloudtrail"}) == []


def test_evaluate_log_empty_service_returns_empty() -> None:
    service = RuleEngineService()
    assert service.evaluate_log({"host": "h", "log_type": "windows_event"}) == []


def test_evaluate_log_alert_carries_correct_fields() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001", title="Windows Login", level="high")])
    log: dict[str, Any] = {"host": "db-01", "log_type": "windows_event", "event_id": "4625"}
    alert = service.evaluate_log(log)[0]
    assert alert.rule_id == "win-001"
    assert alert.rule_title == "Windows Login"
    assert alert.severity == "high"
    assert alert.host == "db-01"
    assert alert.raw_log == log
    assert alert.alert_id  # non-empty UUID


# ---------------------------------------------------------------------------
# hot_reload() — add-only behavior (PRD US 10)
# ---------------------------------------------------------------------------


def test_hot_reload_increases_rule_count() -> None:
    service = RuleEngineService()
    service.hot_reload(_make_payload())
    assert service.rule_count == 1


def test_hot_reload_returns_the_new_sigma_rule() -> None:
    service = RuleEngineService()
    rule = service.hot_reload(_make_payload(rule_id="aws-001", title="AWS Rule", level="high"))
    assert isinstance(rule, SigmaRule)
    assert rule.id == "aws-001"
    assert rule.title == "AWS Rule"
    assert rule.level == "high"


def test_hot_reloaded_rule_matches_subsequent_evaluations() -> None:
    """After hot_reload(), evaluate_log() must apply the new rule."""
    service = RuleEngineService()
    service.hot_reload(_make_payload(
        rule_id="aws-001",
        detection={"sel": {"log_type": "cloudtrail"}, "condition": "sel"},
    ))
    alerts = service.evaluate_log({"host": "h", "log_type": "cloudtrail"})
    assert len(alerts) == 1
    assert alerts[0].rule_id == "aws-001"


def test_hot_reload_is_add_only_existing_rules_still_match() -> None:
    """Reloading a new rule must not remove or replace existing rules."""
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    service.hot_reload(_make_payload(rule_id="aws-001"))
    log: dict[str, Any] = {"host": "h", "log_type": "windows_event", "event_id": "4625"}
    alerts = service.evaluate_log(log)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-001"


def test_hot_reload_multiple_calls_accumulate_all_rules() -> None:
    """Each hot_reload() call appends; all rules remain active."""
    service = RuleEngineService()
    service.hot_reload(_make_payload(
        rule_id="r1",
        detection={"sel": {"log_type": "cloudtrail"}, "condition": "sel"},
    ))
    service.hot_reload(_make_payload(
        rule_id="r2",
        detection={"sel": {"log_type": "windows_event"}, "condition": "sel"},
    ))
    assert service.rule_count == 2
    assert service.evaluate_log({"host": "h", "log_type": "cloudtrail"})[0].rule_id == "r1"
    assert service.evaluate_log({"host": "h", "log_type": "windows_event"})[0].rule_id == "r2"


# ---------------------------------------------------------------------------
# hot_reload() — error handling
# ---------------------------------------------------------------------------


def test_hot_reload_missing_id_raises_rule_engine_error() -> None:
    service = RuleEngineService()
    payload: dict[str, Any] = {
        "title": "T",
        "level": "medium",
        "detection": {"sel": {}, "condition": "sel"},
    }
    with pytest.raises(RuleEngineError):
        service.hot_reload(payload)


def test_hot_reload_missing_detection_raises_rule_engine_error() -> None:
    service = RuleEngineService()
    payload: dict[str, Any] = {"id": "r1", "title": "T", "level": "medium"}
    with pytest.raises(RuleEngineError):
        service.hot_reload(payload)


def test_hot_reload_invalid_payload_does_not_corrupt_rule_set() -> None:
    """A failed hot_reload must not add a partial rule to the active set."""
    service = RuleEngineService([_make_rule("win-001")])
    with pytest.raises(RuleEngineError):
        service.hot_reload({"title": "Incomplete"})  # missing id, level, detection
    assert service.rule_count == 1  # unchanged
