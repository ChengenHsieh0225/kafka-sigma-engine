"""Unit tests for time-window aggregation rule evaluation in RuleEngineService.

Tests verify that the service correctly routes aggregation rules (those with
a 'timeframe' in their detection block) through the sliding-window evaluator,
firing Alerts only when the event count exceeds the threshold.
"""

from typing import Any

import pytest

from src.exceptions import RuleEngineError
from src.models import SigmaRule
from src.rule_engine.service import RuleEngineService


def _agg_rule(
    rule_id: str = "win-brute-force-001",
    title: str = "Brute Force",
    level: str = "high",
    condition: str = "selection | count() by host > 5",
    timeframe: str = "60s",
    selection: dict[str, Any] | None = None,
) -> SigmaRule:
    if selection is None:
        selection = {"log_type": "windows_event", "event_id": "4625"}
    return SigmaRule(
        id=rule_id,
        title=title,
        level=level,
        detection={
            "selection": selection,
            "condition": condition,
            "timeframe": timeframe,
        },
    )


def _failed_login(host: str = "web-01") -> dict[str, Any]:
    return {"host": host, "log_type": "windows_event", "event_id": "4625"}


# ---------------------------------------------------------------------------
# Threshold gating
# ---------------------------------------------------------------------------


def test_no_alert_when_count_at_or_below_threshold() -> None:
    service = RuleEngineService(rules=[_agg_rule()])
    for _ in range(5):
        alerts = service.evaluate_log(_failed_login())
    assert alerts == []


def test_alert_fires_when_count_exceeds_threshold() -> None:
    service = RuleEngineService(rules=[_agg_rule()])
    alerts = []
    for _ in range(6):
        alerts = service.evaluate_log(_failed_login())
    assert len(alerts) == 1


def test_alert_has_correct_metadata() -> None:
    rule = _agg_rule(rule_id="bf-001", title="Brute Force", level="critical")
    service = RuleEngineService(rules=[rule])
    for _ in range(6):
        alerts = service.evaluate_log(_failed_login(host="auth-01"))
    alert = alerts[0]
    assert alert.rule_id == "bf-001"
    assert alert.rule_title == "Brute Force"
    assert alert.severity == "critical"
    assert alert.host == "auth-01"
    assert alert.raw_log["event_id"] == "4625"


def test_alert_continues_firing_above_threshold() -> None:
    service = RuleEngineService(rules=[_agg_rule()])
    for _ in range(6):
        service.evaluate_log(_failed_login())
    alerts = service.evaluate_log(_failed_login())
    assert len(alerts) == 1


def test_aggregation_alert_id_deterministic_across_restarts() -> None:
    """Re-processing the same log sequence on a fresh service yields the same alert_id."""
    ts = "2024-01-01T00:00:00+00:00"
    rule = _agg_rule()
    log = {**_failed_login(), "timestamp": ts}

    def run_sequence() -> str:
        svc = RuleEngineService(rules=[rule])
        result: list = []
        for _ in range(6):
            result = svc.evaluate_log(log)
        return result[0].alert_id

    assert run_sequence() == run_sequence()


def test_aggregation_different_hosts_produce_different_alert_ids() -> None:
    ts = "2024-01-01T00:00:00+00:00"
    rule = _agg_rule()

    def alert_id_for(host: str) -> str:
        svc = RuleEngineService(rules=[rule])
        result: list = []
        for _ in range(6):
            result = svc.evaluate_log({**_failed_login(host=host), "timestamp": ts})
        return result[0].alert_id

    assert alert_id_for("web-01") != alert_id_for("web-02")


# ---------------------------------------------------------------------------
# Non-matching selection
# ---------------------------------------------------------------------------


def test_no_alert_when_selection_does_not_match() -> None:
    service = RuleEngineService(rules=[_agg_rule()])
    non_matching = {"host": "web-01", "log_type": "cloudtrail", "action": "GetObject"}
    for _ in range(10):
        alerts = service.evaluate_log(non_matching)
    assert alerts == []


def test_selection_mismatch_does_not_increment_window() -> None:
    clock_state = [0.0]
    service = RuleEngineService(rules=[_agg_rule()], clock=lambda: clock_state[0])
    non_matching = {"host": "web-01", "log_type": "cloudtrail", "action": "GetObject"}
    for _ in range(10):
        service.evaluate_log(non_matching)
    # Now send matching logs — window count should still start from 0
    for _ in range(5):
        alerts = service.evaluate_log(_failed_login())
    assert alerts == []


# ---------------------------------------------------------------------------
# Per-host isolation
# ---------------------------------------------------------------------------


def test_alert_is_per_host() -> None:
    service = RuleEngineService(rules=[_agg_rule()])
    # Send 6 logs from host-a, none from host-b
    for _ in range(6):
        service.evaluate_log(_failed_login(host="host-a"))
    # host-b has no events → no alert
    alerts = service.evaluate_log(_failed_login(host="host-b"))
    assert alerts == []


def test_hosts_accumulate_independently() -> None:
    service = RuleEngineService(rules=[_agg_rule()])
    for _ in range(3):
        service.evaluate_log(_failed_login(host="host-a"))
        service.evaluate_log(_failed_login(host="host-b"))
    # 3 events per host, threshold is 5 — no alert yet
    assert service.evaluate_log(_failed_login(host="host-a")) == []
    assert service.evaluate_log(_failed_login(host="host-b")) == []


# ---------------------------------------------------------------------------
# Time window eviction
# ---------------------------------------------------------------------------


def test_old_events_evicted_from_window() -> None:
    clock_state = [0.0]
    service = RuleEngineService(rules=[_agg_rule(timeframe="10s")], clock=lambda: clock_state[0])
    for _ in range(5):
        service.evaluate_log(_failed_login())
    clock_state[0] = 15.0  # advance past window
    # Fresh event; only 1 in window — no alert
    alerts = service.evaluate_log(_failed_login())
    assert alerts == []


def test_alert_fires_after_fresh_burst_following_eviction() -> None:
    clock_state = [0.0]
    rule = _agg_rule(condition="selection | count() by host > 2", timeframe="10s")
    service = RuleEngineService(rules=[rule], clock=lambda: clock_state[0])
    for _ in range(2):
        service.evaluate_log(_failed_login())
    clock_state[0] = 15.0  # advance; old events evicted
    service.evaluate_log(_failed_login())   # count=1
    service.evaluate_log(_failed_login())   # count=2
    alerts = service.evaluate_log(_failed_login())  # count=3 → alert
    assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Mixed regular + aggregation rules
# ---------------------------------------------------------------------------


def test_regular_and_aggregation_rules_coexist() -> None:
    regular = SigmaRule(
        id="reg-001",
        title="Regular",
        level="low",
        detection={"sel": {"log_type": "windows_event"}, "condition": "sel"},
    )
    agg = _agg_rule(rule_id="agg-001")
    service = RuleEngineService(rules=[regular, agg])
    # First event: regular rule fires immediately; aggregation rule does not
    alerts = service.evaluate_log(_failed_login())
    rule_ids = {a.rule_id for a in alerts}
    assert "reg-001" in rule_ids
    assert "agg-001" not in rule_ids


def test_both_rules_fire_when_threshold_exceeded() -> None:
    regular = SigmaRule(
        id="reg-001",
        title="Regular",
        level="low",
        detection={"sel": {"log_type": "windows_event"}, "condition": "sel"},
    )
    agg = _agg_rule(rule_id="agg-001")
    service = RuleEngineService(rules=[regular, agg])
    for _ in range(6):
        alerts = service.evaluate_log(_failed_login())
    rule_ids = {a.rule_id for a in alerts}
    assert "reg-001" in rule_ids
    assert "agg-001" in rule_ids


# ---------------------------------------------------------------------------
# Timeframe formats
# ---------------------------------------------------------------------------


def test_timeframe_in_minutes() -> None:
    clock_state = [0.0]
    rule = _agg_rule(
        condition="selection | count() by host > 2",
        timeframe="2m",
    )
    service = RuleEngineService(rules=[rule], clock=lambda: clock_state[0])
    service.evaluate_log(_failed_login())
    clock_state[0] = 61.0  # 61s — within 2 minutes
    service.evaluate_log(_failed_login())
    clock_state[0] = 119.0  # 119s — still within 2 minutes
    alerts = service.evaluate_log(_failed_login())
    assert len(alerts) == 1


def test_timeframe_eviction_in_minutes() -> None:
    clock_state = [0.0]
    rule = _agg_rule(
        condition="selection | count() by host > 2",
        timeframe="1m",
    )
    service = RuleEngineService(rules=[rule], clock=lambda: clock_state[0])
    service.evaluate_log(_failed_login())
    clock_state[0] = 65.0  # beyond 1 minute
    service.evaluate_log(_failed_login())
    alerts = service.evaluate_log(_failed_login())
    # Only 2 fresh events at t=65 and t=65 → count=2, threshold=2 → no alert (strict >)
    assert alerts == []


# ---------------------------------------------------------------------------
# Window cleanup on rule delete
# ---------------------------------------------------------------------------


def test_window_cleared_on_rule_delete() -> None:
    service = RuleEngineService(rules=[_agg_rule()])
    for _ in range(5):
        service.evaluate_log(_failed_login())
    service.apply_rule_update({"op": "delete", "rule_id": "win-brute-force-001"})
    # Re-add the same rule — window state should be gone
    service.apply_rule_update({
        "op": "add",
        "rule": {
            "id": "win-brute-force-001",
            "title": "Brute Force",
            "level": "high",
            "detection": {
                "selection": {"log_type": "windows_event", "event_id": "4625"},
                "condition": "selection | count() by host > 5",
                "timeframe": "60s",
            },
        },
    })
    for _ in range(5):
        alerts = service.evaluate_log(_failed_login())
    assert alerts == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_invalid_aggregation_condition_raises() -> None:
    rule = SigmaRule(
        id="bad-001",
        title="Bad",
        level="low",
        detection={
            "selection": {"log_type": "windows_event"},
            "condition": "selection | sum() by host > 5",  # unsupported aggregation
            "timeframe": "60s",
        },
    )
    service = RuleEngineService(rules=[rule])
    with pytest.raises(RuleEngineError):
        service.evaluate_log(_failed_login())


def test_invalid_timeframe_raises() -> None:
    rule = SigmaRule(
        id="bad-002",
        title="Bad",
        level="low",
        detection={
            "selection": {"log_type": "windows_event"},
            "condition": "selection | count() by host > 5",
            "timeframe": "5d",  # unsupported unit
        },
    )
    service = RuleEngineService(rules=[rule])
    with pytest.raises(RuleEngineError):
        service.evaluate_log(_failed_login())
