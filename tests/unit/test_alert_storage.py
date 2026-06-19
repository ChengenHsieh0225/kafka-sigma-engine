"""Unit tests for the Alert Storage Service.

Tests observable behavior through public interfaces:
- process(alert) → buffer accumulation and size-based flush
- flush() → documents sent to indexer, buffer cleared
- needs_time_flush() → time-based flush detection
"""

from typing import Any

from src.alert_storage.service import AlertStorageService
from src.models import Alert


class FakeIndexer:
    """In-memory indexer that records bulk_index calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, list[dict[str, Any]]]] = []

    async def bulk_index(self, index: str, docs: list[dict[str, Any]]) -> None:
        self.calls.append((index, docs))


def _make_alert(alert_id: str = "alert-001", host: str = "web-01") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="rule-001",
        rule_title="Test Rule",
        severity="medium",
        matched_at="2026-01-01T00:00:00+00:00",
        host=host,
        raw_log={"host": host, "log_type": "windows_event"},
    )


# ---------------------------------------------------------------------------
# process() — buffer accumulation and size-based flush
# ---------------------------------------------------------------------------


async def test_process_no_flush_before_batch_size() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer, batch_size=5)
    for i in range(4):
        await service.process(_make_alert(f"a{i}"))
    assert len(indexer.calls) == 0


async def test_process_auto_flushes_at_batch_size() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer, batch_size=3)
    await service.process(_make_alert("a1"))
    await service.process(_make_alert("a2"))
    assert len(indexer.calls) == 0
    await service.process(_make_alert("a3"))
    assert len(indexer.calls) == 1


async def test_size_flush_resets_buffer_for_next_batch() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer, batch_size=2)
    await service.process(_make_alert("a1"))
    await service.process(_make_alert("a2"))
    await service.process(_make_alert("a3"))
    await service.flush()
    assert len(indexer.calls) == 2
    _, first_batch = indexer.calls[0]
    _, second_batch = indexer.calls[1]
    assert len(first_batch) == 2
    assert len(second_batch) == 1


# ---------------------------------------------------------------------------
# flush() — documents sent to indexer and buffer cleared
# ---------------------------------------------------------------------------


async def test_explicit_flush_after_accumulation_sends_all() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer, batch_size=100)
    for i in range(3):
        await service.process(_make_alert(f"a{i}"))
    await service.flush()
    _, docs = indexer.calls[0]
    assert len(docs) == 3


async def test_flush_sends_documents_to_correct_index() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer, index="sigma-alerts")
    await service.process(_make_alert("a1"))
    await service.flush()
    index_name, _ = indexer.calls[0]
    assert index_name == "sigma-alerts"


async def test_flush_alert_documents_have_correct_fields() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer)
    alert = _make_alert(alert_id="uuid-abc", host="db-01")
    await service.process(alert)
    await service.flush()
    _, docs = indexer.calls[0]
    doc = docs[0]
    assert doc["alert_id"] == "uuid-abc"
    assert doc["rule_id"] == "rule-001"
    assert doc["severity"] == "medium"
    assert doc["host"] == "db-01"
    assert doc["raw_log"] == {"host": "db-01", "log_type": "windows_event"}


async def test_flush_clears_buffer_after_sending() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer)
    await service.process(_make_alert("a1"))
    await service.flush()
    await service.flush()
    assert len(indexer.calls) == 1


async def test_flush_empty_buffer_is_noop() -> None:
    indexer = FakeIndexer()
    service = AlertStorageService(indexer)
    await service.flush()
    assert len(indexer.calls) == 0


# ---------------------------------------------------------------------------
# needs_time_flush() — time-based flush detection
# ---------------------------------------------------------------------------


async def test_needs_time_flush_false_before_interval() -> None:
    t = 0.0
    service = AlertStorageService(FakeIndexer(), flush_interval=5.0, clock=lambda: t)
    await service.process(_make_alert("a1"))
    t = 4.9
    assert not service.needs_time_flush()


async def test_needs_time_flush_true_at_interval() -> None:
    t = 0.0
    service = AlertStorageService(FakeIndexer(), flush_interval=5.0, clock=lambda: t)
    await service.process(_make_alert("a1"))
    t = 5.0
    assert service.needs_time_flush()


async def test_needs_time_flush_false_when_buffer_empty() -> None:
    t = 100.0
    service = AlertStorageService(FakeIndexer(), flush_interval=1.0, clock=lambda: t)
    assert not service.needs_time_flush()


async def test_flush_resets_last_flush_time() -> None:
    t = 0.0
    service = AlertStorageService(FakeIndexer(), flush_interval=5.0, clock=lambda: t)
    await service.process(_make_alert("a1"))
    t = 5.0
    assert service.needs_time_flush()
    await service.flush()
    t = 9.0
    assert not service.needs_time_flush()


async def test_size_flush_also_resets_time_threshold() -> None:
    t = 0.0
    indexer = FakeIndexer()
    service = AlertStorageService(indexer, batch_size=1, flush_interval=5.0, clock=lambda: t)
    t = 3.0
    await service.process(_make_alert("a1"))
    t = 7.0
    assert not service.needs_time_flush()
