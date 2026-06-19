"""Unit tests for shared domain models.

Verifies the observable interface of SigmaRule and Alert:
- field presence and types
- Alert.to_dict() serialisation roundtrip
"""

from src.models import Alert, SigmaRule


def test_sigma_rule_has_required_fields() -> None:
    rule = SigmaRule(
        id="win-failed-login-001",
        title="Windows Failed Login Attempt",
        level="medium",
        detection={"selection": {"log_type": "windows_event"}, "condition": "selection"},
    )
    assert rule.id == "win-failed-login-001"
    assert rule.title == "Windows Failed Login Attempt"
    assert rule.level == "medium"
    assert "condition" in rule.detection


def test_alert_to_dict_contains_all_fields() -> None:
    raw_log = {"timestamp": "2024-01-01T00:00:00Z", "host": "web-01", "log_type": "windows_event"}
    alert = Alert(
        alert_id="uuid-1234",
        rule_id="win-failed-login-001",
        rule_title="Windows Failed Login Attempt",
        severity="medium",
        matched_at="2024-01-01T00:00:00+00:00",
        host="web-01",
        raw_log=raw_log,
    )
    d = alert.to_dict()
    assert d["alert_id"] == "uuid-1234"
    assert d["rule_id"] == "win-failed-login-001"
    assert d["rule_title"] == "Windows Failed Login Attempt"
    assert d["severity"] == "medium"
    assert d["host"] == "web-01"
    assert d["raw_log"] == raw_log


def test_alert_raw_log_defaults_to_empty_dict() -> None:
    alert = Alert(
        alert_id="uuid-5678",
        rule_id="rule-001",
        rule_title="Test Rule",
        severity="low",
        matched_at="2024-01-01T00:00:00+00:00",
        host="host-01",
    )
    assert alert.raw_log == {}
