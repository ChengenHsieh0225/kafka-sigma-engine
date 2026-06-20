"""Integration tests for the end-to-end Kafka → Rule Engine → Elasticsearch pipeline.

These tests require the live Docker Compose stack:
    docker compose up -d kafka kafka-init elasticsearch rule-engine-1 alert-storage

Run with:
    pytest -m integration

Skip during normal unit test runs with:
    pytest -m 'not integration'
"""

import asyncio
import json
import uuid
from typing import Any

import pytest
from aiokafka import AIOKafkaProducer
from elasticsearch import AsyncElasticsearch

KAFKA_BOOTSTRAP = "localhost:9092"
ES_URL = "http://localhost:9200"
ALERT_INDEX = "alerts"
POLL_TIMEOUT_S = 60
POLL_INTERVAL_S = 2


async def _publish_raw_log(raw_log: dict[str, Any]) -> None:
    """Publish a single raw log JSON to the raw-logs Kafka topic."""
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
    await producer.start()
    try:
        host: str = str(raw_log["host"])
        await producer.send_and_wait(
            "raw-logs",
            value=json.dumps(raw_log).encode(),
            key=host.encode(),
        )
    finally:
        await producer.stop()


async def _poll_alert(rule_id: str, host: str) -> list[dict[str, Any]]:
    """Poll Elasticsearch until an alert matching rule_id + host appears or timeout."""
    es = AsyncElasticsearch(ES_URL)
    try:
        for _ in range(POLL_TIMEOUT_S // POLL_INTERVAL_S):
            await asyncio.sleep(POLL_INTERVAL_S)
            try:
                resp = await es.search(
                    index=ALERT_INDEX,
                    query={
                        "bool": {
                            "must": [
                                {"term": {"rule_id": rule_id}},
                                {"term": {"host": host}},
                            ]
                        }
                    },
                    ignore_unavailable=True,
                )
                hits: list[dict[str, Any]] = resp["hits"]["hits"]
                if hits:
                    return hits
            except Exception:  # noqa: BLE001 — tolerate transient ES unavailability
                pass
    finally:
        await es.close()
    return []


@pytest.mark.integration
async def test_windows_failed_login_creates_alert_in_elasticsearch() -> None:
    """Publish a raw log matching windows_failed_login → assert alert stored in ES.

    Verifies: Kafka → Rule Engine (rule match) → alerts topic → Alert Storage → ES.
    Asserts on rule_id, host, and the embedded raw_log (PRD Seam 2).
    """
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "windows_event",
        "event_id": "4625",
        "username": "integ-test-user",
    }

    await _publish_raw_log(raw_log)

    hits = await _poll_alert("win-failed-login-001", host)

    assert hits, (
        f"No alert for rule 'win-failed-login-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "win-failed-login-001"
    assert doc["host"] == host
    assert doc["raw_log"]["host"] == host
    assert doc["raw_log"]["event_id"] == "4625"


@pytest.mark.integration
async def test_cloudtrail_bucket_delete_creates_alert_in_elasticsearch() -> None:
    """Publish a raw log matching cloudtrail_bucket_delete → assert alert stored in ES.

    Verifies: Kafka → Rule Engine (startswith modifier) → alerts topic → ES.
    """
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "cloudtrail",
        "action": "DeleteBucketPolicy",
        "source_ip": "10.0.0.1",
    }

    await _publish_raw_log(raw_log)

    hits = await _poll_alert("aws-s3-delete-001", host)

    assert hits, (
        f"No alert for rule 'aws-s3-delete-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "aws-s3-delete-001"
    assert doc["host"] == host
    assert doc["raw_log"]["action"] == "DeleteBucketPolicy"


@pytest.mark.integration
async def test_non_matching_log_produces_no_alert() -> None:
    """Publish a raw log that matches no rules; confirm no alert is written.

    Uses a unique host so we can query ES confidently for absence.
    Waits one full flush interval (5s) + margin before asserting absence.
    """
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "linux_syslog",
        "process_name": "sshd",
    }

    await _publish_raw_log(raw_log)

    # Wait long enough that any alert would have been written if it existed.
    await asyncio.sleep(10)

    es = AsyncElasticsearch(ES_URL)
    try:
        resp = await es.search(
            index=ALERT_INDEX,
            query={"term": {"host": host}},
            ignore_unavailable=True,
        )
        hits: list[dict[str, Any]] = resp["hits"]["hits"]
    finally:
        await es.close()

    assert not hits, f"Unexpected alert found for non-matching log on host '{host}': {hits}"


async def _publish_alert_direct(alert_payload: dict[str, Any]) -> None:
    """Publish a pre-formed Alert JSON directly to the alerts Kafka topic."""
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
    await producer.start()
    try:
        await producer.send_and_wait(
            "alerts",
            value=json.dumps(alert_payload).encode(),
        )
    finally:
        await producer.stop()


async def _poll_es_count(alert_id: str) -> int:
    """Return the number of ES documents matching the given alert_id."""
    es = AsyncElasticsearch(ES_URL)
    try:
        resp = await es.count(
            index=ALERT_INDEX,
            query={"term": {"alert_id": alert_id}},
            ignore_unavailable=True,
        )
        count: int = resp["count"]
        return count
    finally:
        await es.close()


@pytest.mark.integration
async def test_duplicate_alert_message_is_deduplicated_in_elasticsearch() -> None:
    """Publishing the same alert (same alert_id) twice must produce exactly one ES document.

    Simulates Kafka at-least-once replay: the same Kafka message is consumed twice.
    With _id=alert_id set in the bulk action, the second write is an idempotent upsert
    and must not create a second document (ADR-0014).
    """
    alert_id = f"dedup-test-{uuid.uuid4().hex}"
    alert_payload = {
        "alert_id": alert_id,
        "rule_id": "win-failed-login-001",
        "rule_title": "Windows Failed Login",
        "severity": "medium",
        "matched_at": "2026-01-01T00:00:00+00:00",
        "host": f"dedup-host-{uuid.uuid4().hex[:8]}",
        "raw_log": {"event_id": "4625"},
    }

    # Publish the same alert message twice to simulate at-least-once replay.
    await _publish_alert_direct(alert_payload)
    await _publish_alert_direct(alert_payload)

    # Wait for both messages to be consumed and flushed (flush_interval=5s + margin).
    await asyncio.sleep(12)

    count = await _poll_es_count(alert_id)
    assert count == 1, (
        f"Expected exactly 1 ES document for alert_id '{alert_id}' after deduplication, got {count}"
    )
