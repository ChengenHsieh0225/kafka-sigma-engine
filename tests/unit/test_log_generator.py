"""Unit tests for the log generator module.

Tests observable behavior:
- Raw log schema: required and type-specific optional fields
- Host is used as Kafka message key
- Published value is valid JSON containing required fields
"""

import json

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
