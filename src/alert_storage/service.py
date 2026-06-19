"""Alert Storage micro-batch service for the Kafka Sigma Engine."""

import time
from collections.abc import Callable
from typing import Any, Protocol

from src.models import Alert


class AlertIndexer(Protocol):
    """Structural interface for bulk-indexing Alert documents into a storage backend."""

    async def bulk_index(self, index: str, docs: list[dict[str, Any]]) -> None:
        """Bulk-index a list of Alert documents under *index*."""
        ...


class AlertStorageService:
    """Micro-batch buffer that accumulates Alerts and flushes them to Elasticsearch.

    Args:
        indexer: Storage backend conforming to AlertIndexer.
        index: Elasticsearch index name.
        batch_size: Flush when this many Alerts are buffered (default: 500).
        flush_interval: Flush when this many seconds elapse since last flush (default: 5.0).
        clock: Monotonic clock function; override in tests to control time.
    """

    def __init__(
        self,
        indexer: AlertIndexer,
        index: str = "alerts",
        batch_size: int = 500,
        flush_interval: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._indexer = indexer
        self._index = index
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._clock = clock
        self._buffer: list[Alert] = []
        self._last_flush: float = clock()

    async def process(self, alert: Alert) -> None:
        """Add an Alert to the buffer; flush immediately if batch_size is reached.

        Args:
            alert: The Alert to buffer.
        """
        self._buffer.append(alert)
        if len(self._buffer) >= self._batch_size:
            await self.flush()

    async def flush(self) -> None:
        """Flush all buffered Alerts to the storage backend and reset the timer.

        Does nothing if the buffer is empty.
        """
        if not self._buffer:
            return
        docs = [alert.to_dict() for alert in self._buffer]
        self._buffer = []  # snapshot taken; clear before await to prevent concurrent re-entry
        self._last_flush = self._clock()
        await self._indexer.bulk_index(self._index, docs)

    def needs_time_flush(self) -> bool:
        """Return True if flush_interval has elapsed since the last flush and the buffer is non-empty."""
        return bool(self._buffer) and (self._clock() - self._last_flush) >= self._flush_interval
