# Kafka Sigma Engine

A high-throughput, low-latency log ingestion and threat detection pipeline that simulates a cloud-native XDR (Extended Detection and Response) platform. The system ingests thousands of synthetic security events per second, evaluates them in real time against [Sigma](https://github.com/SigmaHQ/sigma) detection rules using a horizontally-scaled worker pool, and persists matching Alerts to Elasticsearch — all observable through a live Grafana dashboard.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture & Data Flow](#architecture--data-flow)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Testing Guide](#testing-guide)
- [Observability](#observability)

---

## Project Overview

The Kafka Sigma Engine demonstrates the core engineering patterns behind modern SIEM and XDR platforms:

| Capability | Implementation |
|---|---|
| High-throughput ingestion | Kafka `raw-logs` topic with 4 partitions, keyed by source host |
| Parallel threat detection | 4 independent asyncio Rule Engine workers, one per partition |
| In-memory rule evaluation | Level 2 Sigma condition parser — field equality, string modifiers, boolean logic |
| Fault-tolerant processing | Manual at-least-once Kafka offset commits; no logs dropped on restart |
| Live rule delivery | `rule-updates` Kafka topic; new rules fan-out to all workers without restart |
| Efficient alert storage | Micro-batch flush to Elasticsearch `_bulk` API (size ≥ 500 or elapsed ≥ 5 s) |
| Real-time observability | Prometheus metrics + pre-built Grafana dashboard |

**Target metrics:** 10,000+ EPS throughput · sub-millisecond per-event matching latency · zero log loss on worker restart.

---

## Architecture & Data Flow

```
┌─────────────────┐
│  Log Generator  │  Produces synthetic Raw Logs at a configurable EPS rate
│ (Python asyncio)│  Kafka key = host field → deterministic partition routing
└────────┬────────┘
         │ raw-logs (4 partitions, keyed by host)
         ▼
┌────────────────────────────────────────────────────────────────────┐
│                         Apache Kafka                               │
│  raw-logs (4 partitions)  │  alerts (1 partition)  │  rule-updates │
└───┬────────────────────────────────┬───────────────────┬───────────┘
    │                                │                   │
    │  Consumer group: rule-engine   │                   │ Fan-out: unique
    ▼                                │                   │ group per worker
┌──────────────────────────────┐     │                   │
│  Rule Engine Worker ×4       │     │          ┌────────┴────────┐
│  (Python asyncio processes)  │     │          │ rule-updates    │
│                              │     │          │ consumer per    │
│  1. load_rules() on startup  │     │          │ worker (fan-out)│
│  2. consume raw-logs         │     │          └─────────────────┘
│  3. evaluate(log, rules)     │─────┘
│  4. publish Alert to alerts  │
│  5. manual offset commit     │
│  6. expose /metrics :8001    │
└──────────────────────────────┘
         │ alerts (1 partition)
         ▼
┌─────────────────────┐
│  Alert Storage Svc  │  Micro-batch buffer → Elasticsearch _bulk API
│  (Python asyncio)   │  Flush trigger: size ≥ 500 OR elapsed ≥ 5 s
└──────────┬──────────┘
           │
           ▼
┌──────────────────────┐
│  Elasticsearch       │  Index: alerts
│  (single-node)       │  severity indexed as keyword for aggregations
└──────────────────────┘
```

### Kafka Topics

| Topic | Partitions | Key | Purpose |
|---|---|---|---|
| `raw-logs` | 4 | `host` field (UTF-8) | Raw Log stream; partitioned per source host |
| `alerts` | 1 | — | Matched Alert stream consumed by Alert Storage |
| `rule-updates` | 1 | — | Live Sigma Rule delivery; fan-out to all workers |

### Rule Engine Concurrency

Each worker process consumes exactly one partition of `raw-logs` (Kafka distributes them automatically via the `rule-engine` consumer group). The four workers run as independent Docker Compose services, with no shared memory or IPC. Horizontal scaling is done by increasing the replica count to match the partition count.

For `rule-updates`, each worker uses a **unique consumer group ID** (incorporating its `WORKER_ID`) so that every worker receives every new rule — fan-out, not competing consumption.

### Sigma Rule Support (Level 2)

The Rule Engine implements its own YAML-to-condition parser supporting:

- **Field equality:** `event_id: '4625'`
- **String modifiers:** `field|contains`, `field|startswith`, `field|endswith`
- **List values (OR):** `event_id: ['4624', '4625', '4648']`
- **Boolean logic:** `and`, `or`, `not`, parenthesised expressions

Aggregation conditions (`count() > N`) and temporal correlations are out of scope.

---

## Project Structure

```
kafka-sigma-engine/
├── docker-compose.yml          # Full stack: Kafka, ES, Prometheus, Grafana, services
├── pyproject.toml              # Project metadata, pytest config, mypy config
├── requirements.txt            # Pinned runtime dependencies
│
├── prometheus/
│   └── prometheus.yml          # Scrape config: rule-engine-1..4 :8001
│
├── grafana/
│   ├── dashboards/
│   │   └── sigma_engine.json   # Pre-built dashboard: EPS, p99 latency, consumer lag
│   └── provisioning/
│       ├── dashboards/
│       │   └── provider.yml
│       └── datasources/
│           └── prometheus.yml
│
├── services/                   # One Dockerfile per microservice
│   ├── alert_storage/
│   │   └── Dockerfile
│   ├── log_generator/
│   │   └── Dockerfile
│   └── rule_engine/
│       └── Dockerfile
│
├── sigma_rules/                # Bundled Sigma Rule YAML files
│   ├── windows_failed_login.yml      # event_id 4625 → medium
│   └── cloudtrail_bucket_delete.yml  # DeleteBucket → high
│
├── src/
│   ├── exceptions.py           # Domain exception types
│   ├── models.py               # SigmaRule, Alert dataclasses
│   ├── alert_storage/
│   │   ├── main.py             # Service entry point (reads env vars, runs consumer loop)
│   │   └── service.py          # AlertStorageService: micro-batch buffer + flush logic
│   ├── log_generator/
│   │   ├── __main__.py         # Entry point: python -m src.log_generator
│   │   ├── generator.py        # generate_raw_log(): produces windows_event / cloudtrail
│   │   └── service.py          # LogGeneratorService: async publish loop
│   └── rule_engine/
│       ├── main.py             # Entry point: python -m src.rule_engine.main
│       ├── evaluator.py        # evaluate(raw_log, rules) → list[Alert]
│       └── loader.py           # load_rules(path) → list[SigmaRule]
│
└── tests/
    ├── conftest.py
    ├── integration/            # Live-stack tests (require docker compose up)
    └── unit/
        ├── test_alert_storage.py
        ├── test_log_generator.py
        ├── test_models.py
        └── test_rule_engine.py
```

---

## Getting Started

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin)
- Python 3.11+ (for running tests locally)

### 1. Clone the repository

```bash
git clone git@github.com:ChengenHsieh0225/kafka-sigma-engine.git
cd kafka-sigma-engine
```

### 2. Spin up the full stack

This starts Kafka (KRaft mode), Elasticsearch, Prometheus, Grafana, all four Rule Engine workers, the Alert Storage Service, and the Log Generator together. The `--wait` flag blocks until every service with a health check reports healthy.

```bash
docker compose --profile load up -d --wait
```

> **Note:** Always use `--profile load` in every `docker compose` command for this project (including `down`, `logs`, `ps`). Starting the core stack without the profile and adding the Log Generator separately in a second command causes a Docker network reconnection failure.

Expected healthy services: `kafka`, `elasticsearch`, `prometheus`, `grafana`, `rule-engine-1..4`, `alert-storage`, `log-generator`.

### 3.Verify Kafka topics were created:

```bash
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --list
# raw-logs
# alerts
# rule-updates
```

To change the Log Generator rate, set `LOG_GENERATOR_EPS` before starting:

```bash
LOG_GENERATOR_EPS=5000 docker compose --profile load up -d --wait
```

### 4. Verify end-to-end flow

Query Elasticsearch to confirm Alerts are being written:

```bash
curl -s "http://localhost:9200/alerts/_count" | python3 -m json.tool
# { "count": 1234, ... }
```

Fetch a sample Alert document:

```bash
curl -s "http://localhost:9200/alerts/_search?size=1" | python3 -m json.tool
```

### 5. Publish a hot-reloaded Sigma Rule

New rules can be delivered to all running workers without restart. Write a rule YAML to stdout and produce it to the `rule-updates` topic:

```bash
cat sigma_rules/windows_failed_login.yml | \
  docker compose exec -T kafka /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic rule-updates
```

All four Rule Engine workers log rule ingestion on receipt.

### 6. Tear down

```bash
docker compose --profile load down
```

> If you ever see a `network not found` error, it means Docker lost track of the compose network. Run `docker compose --profile load down` followed by `docker compose --profile load up -d --wait` to recover.

---

## Configuration

All services are configured exclusively through environment variables. The values below reflect the defaults set in `docker-compose.yml`.

### Log Generator

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Kafka broker address |
| `LOG_GENERATOR_TOPIC` | `raw-logs` | Target Kafka topic |
| `LOG_GENERATOR_EPS` | `1000` | Target events per second |

### Rule Engine (per worker)

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Kafka broker address |
| `SIGMA_RULES_DIR` | `/app/sigma_rules` | Directory scanned for `*.yml` Sigma Rules on startup |
| `METRICS_PORT` | `8001` | Port for the Prometheus `/metrics` HTTP endpoint |
| `WORKER_ID` | *(set per service)* | Integer 1–4; used to derive a unique `rule-updates` consumer group ID |

### Alert Storage Service

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Kafka broker address |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | Elasticsearch endpoint |
| `BATCH_SIZE` | `500` | Flush the micro-batch buffer when this many Alerts are buffered |
| `FLUSH_INTERVAL` | `5` | Flush the buffer when this many seconds have elapsed since the last flush |

Both `BATCH_SIZE` and `FLUSH_INTERVAL` are performance tuning knobs. Increase `BATCH_SIZE` to reduce `_bulk` call frequency at high Alert volumes; decrease `FLUSH_INTERVAL` to reduce Alert storage latency at low volumes.

---

## Testing Guide

### Install development dependencies

```bash
pip install -e ".[dev]"
```

### Unit tests

Unit tests have no external dependencies and run without Docker. They cover the `evaluate()` matcher function, the `load_rules()` loader, the `AlertStorageService` micro-batch logic, and the `generate_raw_log()` generator.

```bash
pytest tests/unit/
```

Run with verbose output:

```bash
pytest tests/unit/ -v
```

Run static type checking:

```bash
mypy src/
```

### Integration tests

Integration tests run against the live Docker Compose stack. Start the core stack first:

```bash
docker compose up -d --wait
```

Then run the integration suite:

```bash
pytest -m integration tests/integration/
```

Integration tests use real Kafka and Elasticsearch connections — no mocking of external clients. They verify:

- **Infrastructure** (`test_infrastructure.py`): Topics exist with correct partition counts; Elasticsearch cluster is healthy.
- **Log Generator** (`test_log_generator.py`): Messages on `raw-logs` are valid JSON with required fields; Kafka message keys match the `host` field.
- **Rule Engine** (`test_rule_engine.py`): A known Raw Log published to `raw-logs` produces a matching Alert on the `alerts` topic.

To run only the end-to-end test:

```bash
pytest -m integration tests/integration/test_e2e.py -v
```

To exclude integration tests during local development:

```bash
pytest -m "not integration" tests/
```

---

## Observability

### Grafana — `http://localhost:3000`

The Grafana dashboard is provisioned automatically on startup (no login required). It contains three panels:

| Panel | Metric | What it shows |
|---|---|---|
| **EPS Throughput** | `rate(logs_processed_total[1m])` summed across workers | Real-time events per second processed by the Rule Engine |
| **p99 Matching Latency** | `histogram_quantile(0.99, rule_evaluation_duration_seconds_bucket)` | 99th-percentile time to evaluate one Raw Log against all loaded rules |
| **Consumer Lag** | `kafka_consumer_lag` per worker | Backlog of unprocessed messages; spikes indicate the Rule Engine is falling behind the Log Generator |

Navigate to `http://localhost:3000` → **Dashboards** → **Sigma Engine**.

### Prometheus — `http://localhost:9090`

Prometheus scrapes all four Rule Engine workers every 15 seconds. To verify all scrape targets are active:

```
http://localhost:9090/targets
```

All four `rule-engine` targets should show state **UP**.

### Elasticsearch — `http://localhost:9200`

| Query | Description |
|---|---|
| `GET /alerts/_count` | Total Alert documents indexed |
| `GET /alerts/_search?q=severity:high` | Alerts with `high` severity |
| `GET /alerts/_search?q=rule_id:win-failed-login-001` | Alerts from a specific Sigma Rule |

The `severity`, `rule_id`, `host`, and `alert_id` fields are indexed as `keyword`, enabling exact-match filtering and bucket aggregations without full-text analysis.

### Bundled Sigma Rules

Two rules ship with the repository and are loaded on startup by every Rule Engine worker:

| File | Rule ID | Trigger condition | Severity |
|---|---|---|---|
| `windows_failed_login.yml` | `win-failed-login-001` | `log_type = windows_event` AND `event_id = 4625` | `medium` |
| `cloudtrail_bucket_delete.yml` | `aws-s3-delete-001` | `log_type = cloudtrail` AND `action` starts with `DeleteBucket` | `high` |

Add new rules by placing `.yml` files in `sigma_rules/` and restarting the workers, or by publishing rule YAML to the `rule-updates` Kafka topic for zero-downtime delivery.

---

## Key Engineering Decisions

Full rationale for the major architectural choices is recorded in `docs/adr/`:

| ADR | Decision |
|---|---|
| `0001` | Kafka `rule-updates` topic for Sigma Rule delivery (vs. REST API or file-watcher) |
| `0002` | Python asyncio for the Rule Engine (vs. Go) |
| `0003` | Multiple independent asyncio processes as the worker pool (vs. `ProcessPoolExecutor`) |
| `0004` | Elasticsearch for Alert storage (vs. PostgreSQL) |
| `0005` | `raw-logs`: 4 partitions, keyed by source host |
| `0006` | Manual at-least-once offset commits (vs. auto-commit or exactly-once) |
| `0007` | Dual flush triggers: size ≥ 500 OR elapsed ≥ 5 s |
| `0008` | Alert documents embed the full Raw Log (vs. reference by offset) |
| `0009` | Prometheus + Grafana for observability |
