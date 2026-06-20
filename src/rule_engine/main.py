"""Rule Engine entry point for the Kafka Sigma Engine.

Reads configuration from environment variables, loads Sigma Rules, then runs
two concurrent asyncio tasks:
  - A ``raw-logs`` consumer that evaluates each log and publishes Alerts.
  - A ``rule-updates`` fan-out consumer that applies rule lifecycle operations
    (add, update, delete) via the typed JSON envelope format (ADR-0011).

Prometheus metrics are exposed via an HTTP server on METRICS_PORT.
"""

import asyncio
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
from prometheus_client import Counter, Gauge, Histogram, start_http_server

from src.exceptions import RuleEngineError
from src.rule_engine.loader import load_rules
from src.rule_engine.service import RuleEngineService

logger = logging.getLogger(__name__)

_LOGS_PROCESSED: Counter = Counter(
    "logs_processed_total",
    "Total number of raw logs processed by this Rule Engine worker.",
)
_EVAL_DURATION: Histogram = Histogram(
    "rule_evaluation_duration_seconds",
    "Time spent evaluating a single raw log against all loaded Sigma Rules.",
)
_CONSUMER_LAG: Gauge = Gauge(
    "kafka_consumer_lag",
    "Aggregate consumer lag across all raw-logs partitions assigned to this worker.",
)


async def _poll_consumer_lag(consumer: AIOKafkaConsumer) -> None:
    """Background task: refresh _CONSUMER_LAG every 5 seconds."""
    while True:
        await asyncio.sleep(5)
        try:
            partitions = consumer.assignment()
            if not partitions:
                continue
            end_offsets: dict[TopicPartition, int] = await consumer.end_offsets(
                list(partitions)
            )
            total_lag = 0
            for tp, end in end_offsets.items():
                pos = await consumer.position(tp)
                total_lag += max(0, end - pos)
            _CONSUMER_LAG.set(total_lag)
        except Exception:  # noqa: BLE001 — transient Kafka error; metric poll is best-effort
            pass


async def _consume_rule_updates(
    bootstrap: str,
    worker_id: str,
    service: RuleEngineService,
) -> None:
    """Fan-out consumer: apply rule lifecycle operations from ``rule-updates``.

    Each worker uses a unique consumer group ID so every process receives every
    rule update (fan-out, not competing consumers). Supports add, update, and
    delete operations via the typed JSON envelope format (ADR-0011).

    Args:
        bootstrap: Kafka bootstrap servers string.
        worker_id: Unique identifier for this worker process.
        service: Active RuleEngineService; rule lifecycle changes applied via apply_rule_update().
    """
    consumer: AIOKafkaConsumer = AIOKafkaConsumer(
        "rule-updates",
        bootstrap_servers=bootstrap,
        group_id=f"rule-engine-updates-{worker_id}",
        enable_auto_commit=True,
        auto_offset_reset="earliest",
    )
    await consumer.start()
    try:
        async for msg in consumer:
            try:
                data: Any = json.loads(msg.value)
                if not isinstance(data, dict):
                    raise RuleEngineError(
                        f"Rule update envelope must be a JSON object, got {type(data).__name__}"
                    )
                service.apply_rule_update(data)
            except (json.JSONDecodeError, RuleEngineError):
                logger.exception("Skipping malformed rule-update message: %r", msg.value)
    finally:
        await consumer.stop()


async def main() -> None:
    """Run the Rule Engine: consume raw-logs, evaluate Sigma Rules, publish Alerts.

    Environment variables:
        KAFKA_BOOTSTRAP_SERVERS: Kafka broker address (default: ``localhost:9092``).
        SIGMA_RULES_DIR: Directory of ``*.yml`` Sigma Rule files (default: ``sigma_rules``).
        METRICS_PORT: Prometheus HTTP server port (default: ``8001``).
        WORKER_ID: Unique worker identifier used for the rule-updates consumer group.
    """
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    rules_dir = Path(os.environ.get("SIGMA_RULES_DIR", "sigma_rules"))
    metrics_port = int(os.environ.get("METRICS_PORT", "8001"))
    worker_id = os.environ.get("WORKER_ID", str(uuid.uuid4()))

    start_http_server(metrics_port)

    service = RuleEngineService(load_rules(rules_dir))

    producer: AIOKafkaProducer = AIOKafkaProducer(bootstrap_servers=bootstrap)
    await producer.start()

    consumer: AIOKafkaConsumer = AIOKafkaConsumer(
        "raw-logs",
        bootstrap_servers=bootstrap,
        group_id="rule-engine",
        enable_auto_commit=False,
        auto_offset_reset="earliest",
    )
    await consumer.start()

    updates_task = asyncio.create_task(
        _consume_rule_updates(bootstrap, worker_id, service)
    )
    lag_task = asyncio.create_task(_poll_consumer_lag(consumer))

    try:
        async for msg in consumer:
            try:
                raw_log: dict[str, Any] = json.loads(msg.value)
            except json.JSONDecodeError:
                logger.exception("Skipping malformed raw-log message: %r", msg.value)
                continue

            with _EVAL_DURATION.time():
                alerts = service.evaluate_log(raw_log)

            for alert in alerts:
                payload = json.dumps(alert.to_dict()).encode()
                await producer.send_and_wait("alerts", value=payload)

            await consumer.commit()
            _LOGS_PROCESSED.inc()

    finally:
        updates_task.cancel()
        lag_task.cancel()
        await asyncio.gather(updates_task, lag_task, return_exceptions=True)
        await consumer.stop()
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
