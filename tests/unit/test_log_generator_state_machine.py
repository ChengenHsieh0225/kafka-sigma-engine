"""Unit tests for the per-host Log Generator state machine (ADR-0016).

Tests verify the observable behavior of HostStateMachine through its
public interface: the emitted log structure per state.
"""

from typing import Any

import pytest

from src.log_generator.generator import HostStateMachine, State


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------


def test_state_machine_starts_in_idle() -> None:
    sm = HostStateMachine(hosts=["web-01"])
    assert sm.state("web-01") == "idle"


def test_unknown_host_starts_in_idle() -> None:
    sm = HostStateMachine(hosts=[])
    assert sm.state("new-host") == "idle"


# ---------------------------------------------------------------------------
# Log generation per state
# ---------------------------------------------------------------------------


def test_brute_forcing_state_emits_failed_login() -> None:
    sm = HostStateMachine(hosts=["web-01"])
    sm._force_state("web-01", "brute_forcing")
    log = sm.emit("web-01")
    assert log["log_type"] == "windows_event"
    assert str(log["event_id"]) == "4625"
    assert log["host"] == "web-01"


def test_compromised_state_emits_successful_or_privilege_event() -> None:
    sm = HostStateMachine(hosts=["db-01"])
    sm._force_state("db-01", "compromised")
    log = sm.emit("db-01")
    assert log["log_type"] == "windows_event"
    assert str(log["event_id"]) in ("4624", "4672")


def test_lateral_moving_state_emits_suspicious_process() -> None:
    sm = HostStateMachine(hosts=["auth-01"])
    sm._force_state("auth-01", "lateral_moving")
    log = sm.emit("auth-01")
    assert log["log_type"] == "windows_event"
    assert str(log["event_id"]) == "4688"
    assert log["process_name"] in ("cmd.exe", "powershell.exe", "lsass.exe")


def test_idle_state_emits_valid_log_with_required_fields() -> None:
    sm = HostStateMachine(hosts=["web-02"])
    log = sm.emit("web-02")
    assert "host" in log
    assert "timestamp" in log
    assert "log_type" in log


def test_emitted_log_host_matches_argument() -> None:
    sm = HostStateMachine(hosts=["web-01", "db-01"])
    for host in ("web-01", "db-01"):
        log = sm.emit(host)
        assert log["host"] == host


# ---------------------------------------------------------------------------
# State transitions (deterministic via forced state)
# ---------------------------------------------------------------------------


def test_emit_advances_state() -> None:
    """Calling emit() may change the state (probabilistic, just check it's valid)."""
    sm = HostStateMachine(hosts=["web-01"])
    sm._force_state("web-01", "brute_forcing")
    sm.emit("web-01")
    assert sm.state("web-01") in ("idle", "brute_forcing", "compromised")


def test_valid_states_are_four_named_states() -> None:
    """state() always returns one of the four defined states."""
    valid = {"idle", "brute_forcing", "compromised", "lateral_moving"}
    sm = HostStateMachine(hosts=["h"])
    for _ in range(20):
        sm.emit("h")
        assert sm.state("h") in valid


# ---------------------------------------------------------------------------
# LogGeneratorService integration with state machine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_uses_state_machine_when_enabled() -> None:
    """LogGeneratorService with use_state_machine=True sends host-keyed logs."""
    import json
    from unittest.mock import AsyncMock, MagicMock

    from src.log_generator.service import LogGeneratorService

    publisher = MagicMock()
    publisher.send = AsyncMock()
    service = LogGeneratorService(
        publisher=publisher,
        topic="raw-logs",
        hosts=["web-01"],
        use_state_machine=True,
    )
    await service.send_one()
    publisher.send.assert_awaited_once()
    _, kwargs = publisher.send.call_args
    sent_log: dict[str, Any] = json.loads(kwargs["value"])
    assert sent_log["host"] == "web-01"
    assert kwargs["key"] == b"web-01"
