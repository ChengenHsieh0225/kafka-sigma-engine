"""Alert Storage Service entry point for the Kafka Sigma Engine."""

import asyncio
import json
import logging
import os
from typing import Any

from aiokafka import AIOKafkaConsumer
from elasticsearch import AsyncElasticsearch, BadRequestError

from src.alert_storage.service import AlertStorageService
from src.exceptions import AlertStorageError
from src.models import Alert

logger = logging.getLogger(__name__)


class _ESIndexer:
    """Adapts AsyncElasticsearch to the AlertIndexer protocol."""

    def __init__(self, client: AsyncElasticsearch) -> None:
        self._client = client

    async def bulk_index(self, index: str, docs: list[dict[str, Any]]) -> None:
        """Send *docs* to Elasticsearch via the _bulk API."""
        ops: list[Any] = []
        for doc in docs:
            ops.append({"index": {"_index": index, "_id": doc["alert_id"]}})
            ops.append(doc)
        response = await self._client.bulk(operations=ops)
        if response.get("errors"):
            raise AlertStorageError(f"Bulk indexing had partial failures: {response}")


async def _ensure_index(client: AsyncElasticsearch, index: str) -> None:
    """Create the Elasticsearch index with explicit keyword mappings if it does not exist.

    Catches BadRequestError (HTTP 400) to handle the TOCTOU race when multiple
    instances start concurrently and the index is already created.
    """
    try:
        await client.indices.create(
            index=index,
            mappings={
                "properties": {
                    "alert_id": {"type": "keyword"},
                    "rule_id": {"type": "keyword"},
                    "rule_title": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "matched_at": {"type": "date"},
                    "host": {"type": "keyword"},
                    "raw_log": {"type": "object", "dynamic": True},
                }
            },
        )
    except BadRequestError:
        pass  # index already exists — concurrent startup race


async def main() -> None:
    """Run the Alert Storage Service: consume Alerts from Kafka and flush to Elasticsearch."""
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
    batch_size = int(os.environ.get("BATCH_SIZE", "500"))
    flush_interval = float(os.environ.get("FLUSH_INTERVAL", "5"))
    index = "alerts"

    es_client = AsyncElasticsearch(es_url)
    try:
        await _ensure_index(es_client, index)

        service = AlertStorageService(
            indexer=_ESIndexer(es_client),
            index=index,
            batch_size=batch_size,
            flush_interval=flush_interval,
        )

        consumer: AIOKafkaConsumer = AIOKafkaConsumer(
            "alerts",
            bootstrap_servers=bootstrap,
            group_id="alert-storage",
            enable_auto_commit=False,
        )
        await consumer.start()
        try:
            while True:
                records = await consumer.getmany(
                    timeout_ms=int(flush_interval * 1000),
                    max_records=batch_size,
                )
                for tp, msgs in records.items():
                    for msg in msgs:
                        try:
                            data: dict[str, Any] = json.loads(msg.value)
                            alert = Alert(**data)
                        except (json.JSONDecodeError, TypeError):
                            logger.exception("Skipping malformed alert message: %r", msg.value)
                            continue
                        await service.process(alert)
                await service.flush()  # size-triggered (via process) or time-triggered (getmany timeout)
                if records:
                    await consumer.commit()  # advance offset only after confirmed ES flush
        finally:
            try:
                await service.flush()
            except Exception:
                logger.exception("Final flush failed during shutdown")
            try:
                await consumer.commit()
            except Exception:
                logger.exception("Final commit failed during shutdown")
            await consumer.stop()
    finally:
        await es_client.close()


if __name__ == "__main__":
    asyncio.run(main())
