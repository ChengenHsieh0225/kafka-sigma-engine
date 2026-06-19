"""Alert Storage Service entry point for the Kafka Sigma Engine."""

import asyncio
import json
import os
from typing import Any

from aiokafka import AIOKafkaConsumer
from elasticsearch import AsyncElasticsearch

from src.alert_storage.service import AlertStorageService
from src.models import Alert


class _ESIndexer:
    """Adapts AsyncElasticsearch to the AlertIndexer protocol."""

    def __init__(self, client: AsyncElasticsearch) -> None:
        self._client = client

    async def bulk_index(self, index: str, docs: list[dict[str, Any]]) -> None:
        """Send *docs* to Elasticsearch via the _bulk API."""
        ops: list[Any] = []
        for doc in docs:
            ops.append({"index": {"_index": index}})
            ops.append(doc)
        await self._client.bulk(operations=ops)


async def _ensure_index(client: AsyncElasticsearch, index: str) -> None:
    """Create the Elasticsearch index with explicit keyword mappings if it does not exist."""
    if await client.indices.exists(index=index):
        return
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


async def main() -> None:
    """Run the Alert Storage Service: consume Alerts from Kafka and flush to Elasticsearch."""
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
    batch_size = int(os.environ.get("BATCH_SIZE", "500"))
    flush_interval = float(os.environ.get("FLUSH_INTERVAL", "5"))
    index = "alerts"

    es_client = AsyncElasticsearch(es_url)
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
    )
    await consumer.start()

    async def _timer() -> None:
        while True:
            await asyncio.sleep(flush_interval)
            if service.needs_time_flush():
                await service.flush()

    timer_task = asyncio.create_task(_timer())
    try:
        async for msg in consumer:
            data: dict[str, Any] = json.loads(msg.value)
            alert = Alert(**data)
            await service.process(alert)
    finally:
        timer_task.cancel()
        await service.flush()
        await consumer.stop()
        await es_client.close()


if __name__ == "__main__":
    asyncio.run(main())
