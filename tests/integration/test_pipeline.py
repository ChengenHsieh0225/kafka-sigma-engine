"""Integration tests for the end-to-end Kafka → Rule Engine → Elasticsearch pipeline.

Requires a live stack. Two environments are supported:

Docker Compose (default):
    docker compose --profile load up -d --wait
    pytest -m integration tests/integration/

Kubernetes / minikube:
    kubectl port-forward -n kafka-sigma-engine svc/kafka 9092:9092 &
    kubectl port-forward -n kafka-sigma-engine svc/elasticsearch 9200:9200 &
    pytest -m integration tests/integration/

    Or with a custom bootstrap address (e.g. NodePort or /etc/hosts override):
    KAFKA_BOOTSTRAP=localhost:9092 ES_URL=http://localhost:9200 pytest -m integration tests/integration/

Run with:
    pytest -m integration

Skip during normal unit test runs with:
    pytest -m 'not integration'
"""

import asyncio
import json
import os
import uuid
from typing import Any

import pytest
from aiokafka import AIOKafkaProducer
from elasticsearch import AsyncElasticsearch

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
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


async def _publish_rule_update(envelope: dict[str, Any]) -> None:
    """Publish a rule lifecycle envelope to the rule-updates Kafka topic."""
    producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP)
    await producer.start()
    try:
        await producer.send_and_wait(
            "rule-updates",
            value=json.dumps(envelope).encode(),
        )
    finally:
        await producer.stop()


async def _poll_alert_with_log_replay(
    rule_id: str, host: str, raw_log: dict[str, Any]
) -> list[dict[str, Any]]:
    """Poll ES for alert, republishing the raw log every 10s to handle slow rule propagation.

    Replacing a fixed sleep avoids the race where a worker processes the log before
    the rule-update envelope has been consumed and applied.
    """
    republish_every_n = max(1, 10 // POLL_INTERVAL_S)
    es = AsyncElasticsearch(ES_URL)
    try:
        for i in range(POLL_TIMEOUT_S // POLL_INTERVAL_S):
            if i % republish_every_n == 0:
                await _publish_raw_log(raw_log)
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
            except Exception:  # noqa: BLE001
                pass
    finally:
        await es.close()
    return []


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

    hits = await _poll_alert_with_log_replay("win-failed-login-001", host, raw_log)

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

    hits = await _poll_alert_with_log_replay("aws-s3-delete-001", host, raw_log)

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


async def _poll_brute_force_alert(host: str, raw_log: dict[str, Any]) -> list[dict[str, Any]]:
    """Poll for brute-force alert, re-publishing 6 failed logins every 10s.

    Re-publishing the full burst ensures the sliding-window count exceeds the
    threshold even when the first batch was missed due to a consumer-group rebalance.
    """
    republish_every_n = max(1, 10 // POLL_INTERVAL_S)
    es = AsyncElasticsearch(ES_URL)
    try:
        for i in range(POLL_TIMEOUT_S // POLL_INTERVAL_S):
            if i % republish_every_n == 0:
                for _ in range(6):
                    await _publish_raw_log(raw_log)
            await asyncio.sleep(POLL_INTERVAL_S)
            try:
                resp = await es.search(
                    index=ALERT_INDEX,
                    query={
                        "bool": {
                            "must": [
                                {"term": {"rule_id": "win-brute-force-001"}},
                                {"term": {"host": host}},
                            ]
                        }
                    },
                    ignore_unavailable=True,
                )
                hits: list[dict[str, Any]] = resp["hits"]["hits"]
                if hits:
                    return hits
            except Exception:  # noqa: BLE001
                pass
    finally:
        await es.close()
    return []


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


@pytest.mark.integration
async def test_rule_update_add_envelope_creates_alert() -> None:
    """Publish an 'add' rule-update envelope → matching raw log → alert in ES.

    Verifies the typed JSON envelope format (ADR-0011) is handled by all
    rule engine workers: the new rule is applied and subsequent matching
    logs produce alerts.
    """
    rule_id = f"integ-rule-{uuid.uuid4().hex[:8]}"
    log_marker = f"integ-marker-{uuid.uuid4().hex[:8]}"

    add_envelope = {
        "op": "add",
        "rule_id": rule_id,
        "rule": {
            "id": rule_id,
            "title": f"Integration Test Add Rule {rule_id}",
            "level": "high",
            "detection": {
                "sel": {"log_type": log_marker},
                "condition": "sel",
            },
        },
    }
    await _publish_rule_update(add_envelope)

    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": log_marker,
    }

    # Replay the raw log periodically rather than sleeping a fixed duration; this
    # avoids a race where a slow consumer-group rebalance causes the log to be
    # processed before the rule-update envelope is applied.
    hits = await _poll_alert_with_log_replay(rule_id, host, raw_log)
    assert hits, (
        f"No alert for dynamically-added rule '{rule_id}' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == rule_id
    assert doc["severity"] == "high"
    assert doc["host"] == host


@pytest.mark.integration
async def test_windows_successful_login_creates_alert() -> None:
    """Publish a raw log matching win-successful-login-001 → assert alert stored in ES."""
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "windows_event",
        "event_id": "4624",
        "username": "alice",
    }

    hits = await _poll_alert_with_log_replay("win-successful-login-001", host, raw_log)

    assert hits, (
        f"No alert for rule 'win-successful-login-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "win-successful-login-001"
    assert doc["severity"] == "low"
    assert doc["host"] == host
    assert doc["raw_log"]["event_id"] == "4624"


@pytest.mark.integration
async def test_windows_explicit_credentials_creates_alert() -> None:
    """Publish a raw log matching win-explicit-creds-001 → assert alert stored in ES."""
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "windows_event",
        "event_id": "4648",
        "username": "svc-backup",
    }

    hits = await _poll_alert_with_log_replay("win-explicit-creds-001", host, raw_log)

    assert hits, (
        f"No alert for rule 'win-explicit-creds-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "win-explicit-creds-001"
    assert doc["severity"] == "medium"
    assert doc["host"] == host
    assert doc["raw_log"]["event_id"] == "4648"


@pytest.mark.integration
async def test_windows_privilege_use_creates_alert() -> None:
    """Publish a raw log matching win-privilege-use-001 → assert alert stored in ES."""
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "windows_event",
        "event_id": "4672",
        "username": "carol",
    }

    hits = await _poll_alert_with_log_replay("win-privilege-use-001", host, raw_log)

    assert hits, (
        f"No alert for rule 'win-privilege-use-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "win-privilege-use-001"
    assert doc["severity"] == "high"
    assert doc["host"] == host
    assert doc["raw_log"]["event_id"] == "4672"


@pytest.mark.integration
async def test_windows_suspicious_process_creates_alert() -> None:
    """Publish a raw log matching win-suspicious-process-001 → assert alert stored in ES."""
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "windows_event",
        "event_id": "4688",
        "process_name": "powershell.exe",
        "username": "dave",
    }

    hits = await _poll_alert_with_log_replay("win-suspicious-process-001", host, raw_log)

    assert hits, (
        f"No alert for rule 'win-suspicious-process-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "win-suspicious-process-001"
    assert doc["severity"] == "medium"
    assert doc["host"] == host
    assert doc["raw_log"]["event_id"] == "4688"
    assert doc["raw_log"]["process_name"] == "powershell.exe"


@pytest.mark.integration
async def test_cloudtrail_iam_user_create_creates_alert() -> None:
    """Publish a raw log matching aws-iam-create-user-001 → assert alert stored in ES."""
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    raw_log = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "cloudtrail",
        "action": "CreateUser",
        "source_ip": "10.0.0.99",
    }

    hits = await _poll_alert_with_log_replay("aws-iam-create-user-001", host, raw_log)

    assert hits, (
        f"No alert for rule 'aws-iam-create-user-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "aws-iam-create-user-001"
    assert doc["severity"] == "high"
    assert doc["host"] == host
    assert doc["raw_log"]["action"] == "CreateUser"


@pytest.mark.integration
async def test_brute_force_aggregation_rule_creates_alert() -> None:
    """Publish 6 failed login logs from the same host → brute-force alert in ES.

    Verifies: the sliding-window aggregation rule (win-brute-force-001) fires
    after the threshold (> 5 events within 60 s from the same host) is exceeded.
    """
    host = f"test-host-{uuid.uuid4().hex[:8]}"
    failed_login = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": host,
        "log_type": "windows_event",
        "event_id": "4625",
        "username": "brute-force-test-user",
    }

    hits = await _poll_brute_force_alert(host, failed_login)

    assert hits, (
        f"No alert for rule 'win-brute-force-001' on host '{host}' "
        f"appeared in Elasticsearch within {POLL_TIMEOUT_S}s"
    )
    doc = hits[0]["_source"]
    assert doc["rule_id"] == "win-brute-force-001"
    assert doc["severity"] == "high"
    assert doc["host"] == host
