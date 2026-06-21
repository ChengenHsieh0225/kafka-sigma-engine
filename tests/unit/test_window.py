"""Unit tests for the SlidingWindow used in time-window aggregation rules."""

from typing import Callable

import pytest

from src.rule_engine.window import SlidingWindow


def _controlled_clock(start: float = 0.0) -> tuple[Callable[[], float], Callable[[float], None]]:
    """Return a (clock_fn, advance_fn) pair for controlled time in tests."""
    state = [start]

    def clock() -> float:
        return state[0]

    def advance(seconds: float) -> None:
        state[0] += seconds

    return clock, advance


# ---------------------------------------------------------------------------
# Basic add/count behaviour
# ---------------------------------------------------------------------------


def test_empty_window_returns_zero_count() -> None:
    clock, _ = _controlled_clock()
    window = SlidingWindow(now=clock)
    assert window.count("host-1", 60.0) == 0


def test_single_add_returns_count_one() -> None:
    clock, _ = _controlled_clock()
    window = SlidingWindow(now=clock)
    window.add("host-1")
    assert window.count("host-1", 60.0) == 1


def test_multiple_adds_accumulate() -> None:
    clock, _ = _controlled_clock()
    window = SlidingWindow(now=clock)
    for _ in range(5):
        window.add("host-1")
    assert window.count("host-1", 60.0) == 5


# ---------------------------------------------------------------------------
# Per-host isolation
# ---------------------------------------------------------------------------


def test_hosts_are_tracked_independently() -> None:
    clock, _ = _controlled_clock()
    window = SlidingWindow(now=clock)
    for _ in range(3):
        window.add("host-a")
    window.add("host-b")
    assert window.count("host-a", 60.0) == 3
    assert window.count("host-b", 60.0) == 1


def test_unknown_host_returns_zero() -> None:
    clock, _ = _controlled_clock()
    window = SlidingWindow(now=clock)
    window.add("host-1")
    assert window.count("host-unknown", 60.0) == 0


# ---------------------------------------------------------------------------
# Eviction: events outside the window must not be counted
# ---------------------------------------------------------------------------


def test_events_outside_window_are_evicted() -> None:
    clock, advance = _controlled_clock()
    window = SlidingWindow(now=clock)
    window.add("host-1")  # at t=0
    advance(70.0)
    window.add("host-1")  # at t=70
    # only the t=70 event is within a 60-second window
    assert window.count("host-1", 60.0) == 1


def test_events_exactly_at_boundary_are_excluded() -> None:
    clock, advance = _controlled_clock()
    window = SlidingWindow(now=clock)
    window.add("host-1")  # at t=0
    advance(60.0)
    # count at t=60: cutoff=0.0, event at 0.0 is NOT inside (strict >)
    assert window.count("host-1", 60.0) == 0


def test_events_just_inside_boundary_are_included() -> None:
    clock, advance = _controlled_clock()
    window = SlidingWindow(now=clock)
    window.add("host-1")  # at t=0
    advance(59.9)
    # count at t=59.9: cutoff=-0.1, event at 0.0 is inside
    assert window.count("host-1", 60.0) == 1


def test_mixed_old_and_fresh_events() -> None:
    clock, advance = _controlled_clock()
    window = SlidingWindow(now=clock)
    for _ in range(3):
        window.add("host-1")  # at t=0
    advance(70.0)
    for _ in range(4):
        window.add("host-1")  # at t=70
    # only 4 fresh events survive a 60-second window
    assert window.count("host-1", 60.0) == 4


# ---------------------------------------------------------------------------
# Explicit timestamp injection (ts parameter)
# ---------------------------------------------------------------------------


def test_add_with_explicit_ts_overrides_clock() -> None:
    clock, _ = _controlled_clock(start=100.0)
    window = SlidingWindow(now=clock)
    window.add("host-1", ts=0.0)   # injected in the past
    # At t=100, a 60s window means cutoff=40; ts=0 is outside
    assert window.count("host-1", 60.0) == 0


def test_add_with_explicit_ts_within_window() -> None:
    clock, _ = _controlled_clock(start=50.0)
    window = SlidingWindow(now=clock)
    window.add("host-1", ts=30.0)  # at t=30; window at t=50 → cutoff=−10
    assert window.count("host-1", 60.0) == 1
