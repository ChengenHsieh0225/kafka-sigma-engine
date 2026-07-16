"""Unit tests for the log generator module.

Tests observable behavior:
- Raw log schema: required and type-specific optional fields
- Host is used as Kafka message key
- Published value is valid JSON containing required fields
"""

import asyncio
import json
from unittest.mock import patch

import pytest

from src.exceptions import LogGeneratorError
from src.log_generator.generator import generate_raw_log
from src.log_generator.service import LogGeneratorService


class FakePublisher:
    """In-memory Kafka publisher that records calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes, bytes]] = []

    async def send(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
    ) -> None:
        assert value is not None
        assert key is not None
        self.calls.append((topic, key, value))


# --- generate_raw_log ---


def test_generate_raw_log_has_required_fields() -> None:
    log = generate_raw_log()
    assert "timestamp" in log
    assert "host" in log
    assert "log_type" in log


def test_generate_raw_log_host_from_pool() -> None:
    log = generate_raw_log(hosts=["host-a", "host-b"])
    assert log["host"] in {"host-a", "host-b"}


def test_generate_raw_log_log_type_from_pool() -> None:
    log = generate_raw_log(log_types=["windows_event", "cloudtrail"])
    assert log["log_type"] in {"windows_event", "cloudtrail"}


def test_generate_raw_log_windows_event_optional_fields() -> None:
    log = generate_raw_log(hosts=["web-01"], log_types=["windows_event"])
    assert "event_id" in log
    assert "username" in log
    assert "process_name" in log


def test_generate_raw_log_cloudtrail_optional_fields() -> None:
    log = generate_raw_log(hosts=["web-01"], log_types=["cloudtrail"])
    assert "action" in log
    assert "source_ip" in log


def test_generate_raw_log_empty_hosts_raises() -> None:
    with pytest.raises(LogGeneratorError):
        generate_raw_log(hosts=[])


def test_generate_raw_log_empty_log_types_raises() -> None:
    with pytest.raises(LogGeneratorError):
        generate_raw_log(log_types=[])


# --- LogGeneratorService ---


async def test_service_send_one_publishes_to_topic() -> None:
    publisher = FakePublisher()
    service = LogGeneratorService(
        publisher=publisher,
        topic="raw-logs",
        hosts=["web-01"],
        log_types=["windows_event"],
    )
    await service.send_one()
    assert len(publisher.calls) == 1
    topic, _, _ = publisher.calls[0]
    assert topic == "raw-logs"


async def test_service_send_one_uses_host_as_key() -> None:
    publisher = FakePublisher()
    service = LogGeneratorService(
        publisher=publisher,
        topic="raw-logs",
        hosts=["web-01"],
        log_types=["windows_event"],
    )
    await service.send_one()
    _, key, _ = publisher.calls[0]
    assert key == b"web-01"


async def test_service_send_one_publishes_valid_json() -> None:
    publisher = FakePublisher()
    service = LogGeneratorService(
        publisher=publisher,
        topic="raw-logs",
        hosts=["web-01"],
        log_types=["windows_event"],
    )
    await service.send_one()
    _, _, value = publisher.calls[0]
    log = json.loads(value)
    assert "timestamp" in log
    assert "host" in log
    assert "log_type" in log


# --- EPS accuracy (time-compensation loop) ---


async def test_run_sleep_compensates_for_send_overhead() -> None:
    """Sleep duration shrinks by exactly the send overhead each iteration."""
    EPS = 1000
    SEND_COST = 0.0003  # 0.3 ms per send; target interval = 1.0 ms

    t = [0.0]
    sleep_calls: list[float] = []

    class CostlyPublisher:
        async def send(self, topic: str, *, value: bytes | None = None, key: bytes | None = None) -> None:
            t[0] += SEND_COST

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)
        t[0] += max(0.0, delay)
        if len(sleep_calls) >= 5:
            raise asyncio.CancelledError()

    service = LogGeneratorService(
        publisher=CostlyPublisher(), topic="raw-logs", hosts=["host-001"]
    )

    with patch("asyncio.sleep", side_effect=fake_sleep):
        with pytest.raises(asyncio.CancelledError):
            await service.run(eps=EPS, _clock=lambda: t[0])

    expected = 1.0 / EPS - SEND_COST  # 0.7 ms
    for d in sleep_calls:
        assert abs(d - expected) < 1e-10, f"sleep {d} ≠ expected {expected}"

    # total elapsed time = N / EPS (send cost + sleep = 1/EPS per iteration)
    assert abs(t[0] - len(sleep_calls) / EPS) < 1e-10


async def test_run_skips_sleep_when_behind_schedule() -> None:
    """When send_one() exceeds 1/eps, sleep is skipped entirely to catch up."""
    EPS = 1000
    SEND_COST = 0.002  # 2 ms per send, more than the 1 ms target interval
    N = 4

    t = [0.0]
    sleep_calls: list[float] = []

    class SlowPublisher:
        def __init__(self) -> None:
            self._count = 0

        async def send(self, topic: str, *, value: bytes | None = None, key: bytes | None = None) -> None:
            t[0] += SEND_COST
            self._count += 1
            if self._count >= N:
                raise asyncio.CancelledError()

    async def fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)
        t[0] += max(0.0, delay)

    service = LogGeneratorService(
        publisher=SlowPublisher(), topic="raw-logs", hosts=["host-001"]
    )

    with patch("asyncio.sleep", side_effect=fake_sleep):
        with pytest.raises(asyncio.CancelledError):
            await service.run(eps=EPS, _clock=lambda: t[0])

    assert sleep_calls == [], "sleep should never be called when send_one() is slower than 1/eps"
