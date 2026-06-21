"""Unit tests for the five new Slice 4 single-log Sigma rule YAML files.

Tests verify that each rule YAML loads correctly and matches (or rejects)
the expected raw log shapes via the public evaluate() interface.
"""

from pathlib import Path
from typing import Any

import pytest

from src.models import SigmaRule
from src.rule_engine.evaluator import evaluate
from src.rule_engine.loader import load_rules

SIGMA_RULES_DIR = Path(__file__).parent.parent.parent / "sigma_rules"


def _load_rule_by_id(rule_id: str) -> SigmaRule:
    rules = load_rules(SIGMA_RULES_DIR)
    for r in rules:
        if r.id == rule_id:
            return r
    raise AssertionError(f"Rule id '{rule_id}' not found; available: {[r.id for r in rules]}")


# ---------------------------------------------------------------------------
# Rule: Windows Successful Login (event_id 4624)
# ---------------------------------------------------------------------------


def test_windows_successful_login_rule_loads() -> None:
    rule = _load_rule_by_id("win-successful-login-001")
    assert rule.level == "low"
    assert rule.title


def test_windows_successful_login_matches_4624() -> None:
    rule = _load_rule_by_id("win-successful-login-001")
    raw_log: dict[str, Any] = {
        "host": "web-01",
        "log_type": "windows_event",
        "event_id": "4624",
        "username": "alice",
    }
    alerts = evaluate(raw_log, [rule])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-successful-login-001"
    assert alerts[0].severity == "low"
    assert alerts[0].host == "web-01"


def test_windows_successful_login_matches_integer_event_id() -> None:
    rule = _load_rule_by_id("win-successful-login-001")
    raw_log: dict[str, Any] = {
        "host": "db-01",
        "log_type": "windows_event",
        "event_id": 4624,
    }
    assert len(evaluate(raw_log, [rule])) == 1


def test_windows_successful_login_no_match_for_other_event_id() -> None:
    rule = _load_rule_by_id("win-successful-login-001")
    raw_log: dict[str, Any] = {
        "host": "web-01",
        "log_type": "windows_event",
        "event_id": "4625",
    }
    assert evaluate(raw_log, [rule]) == []


def test_windows_successful_login_no_match_for_cloudtrail() -> None:
    rule = _load_rule_by_id("win-successful-login-001")
    raw_log: dict[str, Any] = {
        "host": "web-01",
        "log_type": "cloudtrail",
        "action": "GetObject",
    }
    assert evaluate(raw_log, [rule]) == []


# ---------------------------------------------------------------------------
# Rule: Windows Logon Using Explicit Credentials (event_id 4648)
# ---------------------------------------------------------------------------


def test_windows_explicit_credentials_rule_loads() -> None:
    rule = _load_rule_by_id("win-explicit-creds-001")
    assert rule.level == "medium"
    assert rule.title


def test_windows_explicit_credentials_matches_4648() -> None:
    rule = _load_rule_by_id("win-explicit-creds-001")
    raw_log: dict[str, Any] = {
        "host": "auth-01",
        "log_type": "windows_event",
        "event_id": "4648",
        "username": "svc-backup",
    }
    alerts = evaluate(raw_log, [rule])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-explicit-creds-001"
    assert alerts[0].severity == "medium"


def test_windows_explicit_credentials_no_match_for_4624() -> None:
    rule = _load_rule_by_id("win-explicit-creds-001")
    raw_log: dict[str, Any] = {
        "host": "web-01",
        "log_type": "windows_event",
        "event_id": "4624",
    }
    assert evaluate(raw_log, [rule]) == []


# ---------------------------------------------------------------------------
# Rule: Windows Special Privileges Assigned to New Logon (event_id 4672)
# ---------------------------------------------------------------------------


def test_windows_privilege_use_rule_loads() -> None:
    rule = _load_rule_by_id("win-privilege-use-001")
    assert rule.level == "high"
    assert rule.title


def test_windows_privilege_use_matches_4672() -> None:
    rule = _load_rule_by_id("win-privilege-use-001")
    raw_log: dict[str, Any] = {
        "host": "db-01",
        "log_type": "windows_event",
        "event_id": "4672",
        "username": "carol",
    }
    alerts = evaluate(raw_log, [rule])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-privilege-use-001"
    assert alerts[0].severity == "high"


def test_windows_privilege_use_no_match_for_4625() -> None:
    rule = _load_rule_by_id("win-privilege-use-001")
    raw_log: dict[str, Any] = {
        "host": "web-01",
        "log_type": "windows_event",
        "event_id": "4625",
    }
    assert evaluate(raw_log, [rule]) == []


# ---------------------------------------------------------------------------
# Rule: Windows Suspicious Process Creation (event_id 4688, process_name filter)
# ---------------------------------------------------------------------------


def test_windows_suspicious_process_rule_loads() -> None:
    rule = _load_rule_by_id("win-suspicious-process-001")
    assert rule.level == "medium"
    assert rule.title


def test_windows_suspicious_process_matches_powershell() -> None:
    rule = _load_rule_by_id("win-suspicious-process-001")
    raw_log: dict[str, Any] = {
        "host": "web-02",
        "log_type": "windows_event",
        "event_id": "4688",
        "process_name": "powershell.exe",
    }
    alerts = evaluate(raw_log, [rule])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "win-suspicious-process-001"


def test_windows_suspicious_process_matches_cmd() -> None:
    rule = _load_rule_by_id("win-suspicious-process-001")
    raw_log: dict[str, Any] = {
        "host": "web-02",
        "log_type": "windows_event",
        "event_id": "4688",
        "process_name": "cmd.exe",
    }
    assert len(evaluate(raw_log, [rule])) == 1


def test_windows_suspicious_process_no_match_for_benign_process() -> None:
    rule = _load_rule_by_id("win-suspicious-process-001")
    raw_log: dict[str, Any] = {
        "host": "web-02",
        "log_type": "windows_event",
        "event_id": "4688",
        "process_name": "svchost.exe",
    }
    assert evaluate(raw_log, [rule]) == []


def test_windows_suspicious_process_no_match_wrong_event_id() -> None:
    rule = _load_rule_by_id("win-suspicious-process-001")
    raw_log: dict[str, Any] = {
        "host": "web-02",
        "log_type": "windows_event",
        "event_id": "4624",
        "process_name": "powershell.exe",
    }
    assert evaluate(raw_log, [rule]) == []


# ---------------------------------------------------------------------------
# Rule: CloudTrail IAM User Created (action: CreateUser)
# ---------------------------------------------------------------------------


def test_cloudtrail_iam_user_create_rule_loads() -> None:
    rule = _load_rule_by_id("aws-iam-create-user-001")
    assert rule.level == "high"
    assert rule.title


def test_cloudtrail_iam_user_create_matches_create_user() -> None:
    rule = _load_rule_by_id("aws-iam-create-user-001")
    raw_log: dict[str, Any] = {
        "host": "db-02",
        "log_type": "cloudtrail",
        "action": "CreateUser",
        "source_ip": "10.0.0.5",
    }
    alerts = evaluate(raw_log, [rule])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "aws-iam-create-user-001"
    assert alerts[0].severity == "high"


def test_cloudtrail_iam_user_create_no_match_for_other_actions() -> None:
    rule = _load_rule_by_id("aws-iam-create-user-001")
    for action in ("GetObject", "ListBuckets", "PutObject", "DeleteBucket"):
        raw_log: dict[str, Any] = {
            "host": "db-02",
            "log_type": "cloudtrail",
            "action": action,
        }
        assert evaluate(raw_log, [rule]) == [], f"Rule should not match action '{action}'"


def test_cloudtrail_iam_user_create_no_match_for_windows_event() -> None:
    rule = _load_rule_by_id("aws-iam-create-user-001")
    raw_log: dict[str, Any] = {
        "host": "web-01",
        "log_type": "windows_event",
        "event_id": "4624",
    }
    assert evaluate(raw_log, [rule]) == []


# ---------------------------------------------------------------------------
# Rule: Windows Brute Force (aggregation, event_id 4625 > 5 in 60s)
# ---------------------------------------------------------------------------


def test_windows_brute_force_rule_loads() -> None:
    rule = _load_rule_by_id("win-brute-force-001")
    assert rule.level == "high"
    assert "timeframe" in rule.detection
    assert rule.detection["timeframe"] == "60s"


def test_windows_brute_force_condition_contains_count() -> None:
    rule = _load_rule_by_id("win-brute-force-001")
    assert "count()" in rule.detection["condition"]
    assert "> 5" in rule.detection["condition"]


# ---------------------------------------------------------------------------
# All 8 rules load from disk (7 existing + 1 aggregation)
# ---------------------------------------------------------------------------


def test_sigma_rules_directory_contains_eight_rules() -> None:
    rules = load_rules(SIGMA_RULES_DIR)
    assert len(rules) == 8, (
        f"Expected 8 rules (7 existing + 1 aggregation), found {len(rules)}: {[r.id for r in rules]}"
    )


def test_all_rule_ids_are_unique() -> None:
    rules = load_rules(SIGMA_RULES_DIR)
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), f"Duplicate rule IDs found: {ids}"
