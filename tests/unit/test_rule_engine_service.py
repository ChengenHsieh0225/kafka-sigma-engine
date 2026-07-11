"""Unit tests for RuleEngineService.

Tests observable behavior through the public interface:
- evaluate_log(raw_log) -> list[Alert]
- apply_rule_update(envelope) -> SigmaRule | None (ADR-0011 typed envelope)
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
# apply_rule_update() — add: accumulation and isolation behavior
# ---------------------------------------------------------------------------


def test_add_does_not_remove_existing_rules() -> None:
    """Adding a new rule must not remove or replace existing rules."""
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    service.apply_rule_update({"op": "add", "rule": _make_payload(rule_id="aws-001")})
    log: dict[str, Any] = {"host": "h", "log_type": "windows_event", "event_id": "4625"}
    alerts = service.evaluate_log(log)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-001"


def test_multiple_adds_accumulate_all_rules() -> None:
    """Each add operation appends; all rules remain active."""
    service = RuleEngineService()
    service.apply_rule_update({"op": "add", "rule": _make_payload(
        rule_id="r1",
        detection={"sel": {"log_type": "cloudtrail"}, "condition": "sel"},
    )})
    service.apply_rule_update({"op": "add", "rule": _make_payload(
        rule_id="r2",
        detection={"sel": {"log_type": "windows_event"}, "condition": "sel"},
    )})
    assert service.rule_count == 2
    assert service.evaluate_log({"host": "h", "log_type": "cloudtrail"})[0].rule_id == "r1"
    assert service.evaluate_log({"host": "h", "log_type": "windows_event"})[0].rule_id == "r2"


# ---------------------------------------------------------------------------
# apply_rule_update() — add: error handling
# ---------------------------------------------------------------------------


def test_add_missing_rule_id_raises_rule_engine_error() -> None:
    service = RuleEngineService()
    payload: dict[str, Any] = {
        "title": "T",
        "level": "medium",
        "detection": {"sel": {}, "condition": "sel"},
    }
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "add", "rule": payload})


def test_add_missing_detection_raises_rule_engine_error() -> None:
    service = RuleEngineService()
    payload: dict[str, Any] = {"id": "r1", "title": "T", "level": "medium"}
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "add", "rule": payload})


# ---------------------------------------------------------------------------
# apply_rule_update() — add operation (ADR-0011 typed envelope)
# ---------------------------------------------------------------------------


def _make_envelope(
    op: str = "add",
    rule_id: str = "new-001",
    rule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {"op": op, "rule_id": rule_id}
    if rule is not None:
        envelope["rule"] = rule
    return envelope


def test_apply_rule_update_add_increases_rule_count() -> None:
    service = RuleEngineService()
    service.apply_rule_update(_make_envelope(op="add", rule_id="aws-001", rule=_make_payload(rule_id="aws-001")))
    assert service.rule_count == 1


def test_apply_rule_update_add_returns_new_sigma_rule() -> None:
    service = RuleEngineService()
    result = service.apply_rule_update(
        _make_envelope(op="add", rule_id="aws-001", rule=_make_payload(rule_id="aws-001", title="AWS Rule", level="high"))
    )
    assert isinstance(result, SigmaRule)
    assert result.id == "aws-001"
    assert result.title == "AWS Rule"
    assert result.level == "high"


def test_apply_rule_update_add_rule_matches_future_evaluations() -> None:
    service = RuleEngineService()
    service.apply_rule_update(_make_envelope(
        op="add",
        rule_id="aws-001",
        rule=_make_payload(rule_id="aws-001", detection={"sel": {"log_type": "cloudtrail"}, "condition": "sel"}),
    ))
    alerts = service.evaluate_log({"host": "h", "log_type": "cloudtrail"})
    assert len(alerts) == 1
    assert alerts[0].rule_id == "aws-001"


# ---------------------------------------------------------------------------
# apply_rule_update() — update operation
# ---------------------------------------------------------------------------


def test_apply_rule_update_update_replaces_existing_rule() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001", level="low")])
    service.apply_rule_update(_make_envelope(
        op="update",
        rule_id="win-001",
        rule={"id": "win-001", "title": "Updated", "level": "critical",
              "detection": {"selection": {"log_type": "windows_event", "event_id": "4625"}, "condition": "selection"}},
    ))
    assert service.rule_count == 1


def test_apply_rule_update_update_new_version_takes_effect_in_evaluation() -> None:
    old_det = {"sel": {"log_type": "cloudtrail"}, "condition": "sel"}
    new_det = {"sel": {"log_type": "windows_event", "event_id": "4625"}, "condition": "sel"}
    service = RuleEngineService([SigmaRule(id="r1", title="Old", level="low", detection=old_det)])
    service.apply_rule_update(_make_envelope(
        op="update",
        rule_id="r1",
        rule={"id": "r1", "title": "New", "level": "high", "detection": new_det},
    ))
    assert service.evaluate_log({"host": "h", "log_type": "cloudtrail"}) == []
    alerts = service.evaluate_log({"host": "h", "log_type": "windows_event", "event_id": "4625"})
    assert len(alerts) == 1
    assert alerts[0].severity == "high"


def test_apply_rule_update_update_non_existent_rule_upserts() -> None:
    service = RuleEngineService()
    service.apply_rule_update(_make_envelope(op="update", rule_id="new-rule", rule=_make_payload(rule_id="new-rule")))
    assert service.rule_count == 1


def test_apply_rule_update_update_returns_updated_sigma_rule() -> None:
    service = RuleEngineService([_make_rule(rule_id="r1")])
    result = service.apply_rule_update(_make_envelope(
        op="update",
        rule_id="r1",
        rule={"id": "r1", "title": "Updated", "level": "critical", "detection": {"sel": {}, "condition": "sel"}},
    ))
    assert isinstance(result, SigmaRule)
    assert result.title == "Updated"
    assert result.level == "critical"


# ---------------------------------------------------------------------------
# apply_rule_update() — delete operation
# ---------------------------------------------------------------------------


def test_apply_rule_update_delete_removes_rule() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    service.apply_rule_update({"op": "delete", "rule_id": "win-001"})
    assert service.rule_count == 0


def test_apply_rule_update_delete_returns_none() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    result = service.apply_rule_update({"op": "delete", "rule_id": "win-001"})
    assert result is None


def test_apply_rule_update_delete_stops_future_evaluations() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    service.apply_rule_update({"op": "delete", "rule_id": "win-001"})
    assert service.evaluate_log({"host": "h", "log_type": "windows_event", "event_id": "4625"}) == []


def test_apply_rule_update_delete_non_existent_rule_is_noop() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    service.apply_rule_update({"op": "delete", "rule_id": "does-not-exist"})
    assert service.rule_count == 1


# ---------------------------------------------------------------------------
# apply_rule_update() — error handling
# ---------------------------------------------------------------------------


def test_apply_rule_update_missing_op_raises_rule_engine_error() -> None:
    service = RuleEngineService()
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"rule_id": "r1", "rule": _make_payload()})


def test_apply_rule_update_update_missing_rule_id_raises_rule_engine_error() -> None:
    service = RuleEngineService()
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "update", "rule": _make_payload()})


def test_apply_rule_update_add_without_rule_id_succeeds() -> None:
    service = RuleEngineService()
    result = service.apply_rule_update({"op": "add", "rule": _make_payload(rule_id="new-001")})
    assert isinstance(result, SigmaRule)
    assert result.id == "new-001"
    assert service.rule_count == 1


def test_apply_rule_update_update_id_mismatch_raises_rule_engine_error() -> None:
    service = RuleEngineService([_make_rule(rule_id="win-001")])
    with pytest.raises(RuleEngineError):
        service.apply_rule_update(_make_envelope(
            op="update",
            rule_id="win-001",
            rule={"id": "win-002", "title": "Mismatch", "level": "medium",
                  "detection": {"sel": {}, "condition": "sel"}},
        ))


def test_apply_rule_update_unknown_op_raises_rule_engine_error() -> None:
    service = RuleEngineService()
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "replace", "rule_id": "r1", "rule": _make_payload()})


def test_apply_rule_update_add_missing_rule_field_raises() -> None:
    service = RuleEngineService()
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "add", "rule_id": "r1"})


def test_apply_rule_update_update_missing_rule_field_raises() -> None:
    service = RuleEngineService()
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "update", "rule_id": "r1"})


def test_apply_rule_update_add_missing_rule_subfield_raises() -> None:
    service = RuleEngineService()
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "add", "rule_id": "r1", "rule": {"id": "r1", "title": "T"}})


def test_apply_rule_update_error_does_not_corrupt_rule_set() -> None:
    service = RuleEngineService([_make_rule("win-001")])
    with pytest.raises(RuleEngineError):
        service.apply_rule_update({"op": "add", "rule_id": "r1", "rule": {"incomplete": True}})
    assert service.rule_count == 1
