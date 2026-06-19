"""Rule Engine entry point for the Kafka Sigma Engine.

Reads configuration from environment variables, loads Sigma Rules, then runs
two concurrent asyncio tasks:
  - A ``raw-logs`` consumer that evaluates each log and publishes Alerts.
  - A ``rule-updates`` fan-out consumer that hot-reloads new rules add-only.

Prometheus metrics are exposed via an HTTP server on METRICS_PORT.
"""

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
from prometheus_client import Counter, Gauge, Histogram, start_http_server

from src.exceptions import RuleEngineError
from src.models import SigmaRule
from src.rule_engine.evaluator import evaluate
from src.rule_engine.loader import load_rules

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
    rules: list[SigmaRule],
) -> None:
    """Fan-out consumer: hot-reload new Sigma Rules published to ``rule-updates``.

    Each worker uses a unique consumer group ID so every process receives every
    rule update (fan-out, not competing consumers).  Reloading is add-only per
    PRD User Story 10: removing or replacing a rule requires a worker restart.

    Args:
        bootstrap: Kafka bootstrap servers string.
        worker_id: Unique identifier for this worker process.
        rules: Shared in-memory rule list; new rules are appended.

    Raises:
        RuleEngineError: If a published rule payload is missing a required field.
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
            data: dict[str, Any] = json.loads(msg.value)
            try:
                rule = SigmaRule(
                    id=data["id"],
                    title=data["title"],
                    level=data["level"],
                    detection=data["detection"],
                )
            except KeyError as exc:
                raise RuleEngineError(
                    f"Hot-reloaded rule payload is missing required field: {exc}"
                ) from exc
            rules.append(rule)
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

    rules: list[SigmaRule] = load_rules(rules_dir)

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
        _consume_rule_updates(bootstrap, worker_id, rules)
    )
    lag_task = asyncio.create_task(_poll_consumer_lag(consumer))

    try:
        async for msg in consumer:
            raw_log: dict[str, Any] = json.loads(msg.value)

            with _EVAL_DURATION.time():
                alerts = evaluate(raw_log, rules)

            for alert in alerts:
                payload = json.dumps(alert.to_dict()).encode()
                await producer.send_and_wait("alerts", value=payload)

            await consumer.commit()
            _LOGS_PROCESSED.inc()

    finally:
        updates_task.cancel()
        lag_task.cancel()
        await consumer.stop()
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
