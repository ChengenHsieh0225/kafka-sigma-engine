# Kafka Sigma Engine

A high-throughput, low-latency log ingestion and threat detection pipeline that simulates a cloud-native XDR (Extended Detection and Response) platform. The system ingests thousands of synthetic security events per second, evaluates them in real time against [Sigma](https://github.com/SigmaHQ/sigma) detection rules using a horizontally-scaled worker pool, and persists matching Alerts to Elasticsearch — all observable through a live Grafana dashboard.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture & Data Flow](#architecture--data-flow)
- [Project Structure](#project-structure)
- [Getting Started — Docker Compose](#getting-started--docker-compose)
- [Getting Started — Kubernetes (minikube)](#getting-started--kubernetes-minikube)
- [Configuration](#configuration)
- [Testing Guide](#testing-guide)
- [Observability](#observability)
- [Key Engineering Decisions](#key-engineering-decisions)

---

## Project Overview

| Capability | Implementation |
|---|---|
| High-throughput ingestion | Kafka `raw-logs` topic with 8 partitions, keyed by source host |
| Parallel threat detection | Up to 8 asyncio Rule Engine workers (one per partition) |
| In-memory rule evaluation | Level 2 Sigma condition parser — field equality, string modifiers, boolean logic |
| Time-window aggregation | Per-worker sliding window detects burst patterns (e.g. brute-force) without external state |
| Fault-tolerant processing | Manual at-least-once Kafka offset commits; no logs dropped on restart |
| Live rule management | `rule-updates` topic with typed JSON envelope — add, update, and delete rules without restart |
| Alert deduplication | Elasticsearch `_id` set to `alert_id`; idempotent upsert eliminates Kafka at-least-once duplicates |
| Realistic load generation | Per-host state machine produces correlated attack sequences; HTTP admin endpoint for runtime EPS control |
| Efficient alert storage | Micro-batch flush to Elasticsearch `_bulk` API (size ≥ 500 or elapsed ≥ 5 s) |
| Real-time observability | Prometheus metrics + pre-built Grafana dashboard |
| Kubernetes deployment | Full stack in `k8s/` targeting minikube; Rule Engine scales to 8 replicas with `kubectl scale` |

**Target metrics:** 10,000+ EPS throughput · sub-millisecond per-event matching latency · zero log loss on worker restart.

---

## Architecture & Data Flow

```
┌───────────────────────────────────────────────────┐
│  Log Generator  (Python asyncio)                  │
│                                                   │
│  HostStateMachine — per-host states:              │
│    idle → brute_forcing → compromised             │
│         → lateral_moving                          │
│                                                   │
│  HTTP admin  POST /rate  GET /rate  :8080         │
└───────────────────────┬───────────────────────────┘
                        │ raw-logs (8 partitions, keyed by host)
                        ▼
┌───────────────────────────────────────────────────────────────────┐
│                          Apache Kafka                             │
│  raw-logs (8 partitions) │ alerts (1 partition) │ rule-updates   │
└───┬───────────────────────────────┬──────────────────┬───────────┘
    │                               │                  │
    │ Consumer group: rule-engine   │                  │ Fan-out: unique
    ▼                               │                  │ group per worker
┌──────────────────────────────┐    │         ┌────────┴────────┐
│  Rule Engine Worker ×N       │    │         │ rule-updates    │
│  (N ≤ 8, Python asyncio)     │    │         │ consumer per    │
│                              │    │         │ worker (fan-out)│
│  RuleEngineService           │    │         └─────────────────┘
│  ├─ load_rules() on startup  │    │
│  ├─ apply_rule_update()      │    │   Envelope format (ADR-0011):
│  │  add | update | delete    │    │   {"op":"add"|"update"|"delete",
│  ├─ evaluate() — single-log  │────┘    "rule_id":"...", "rule":{...}}
│  ├─ SlidingWindow — bursts   │
│  └─ /metrics :8001           │
└──────────────────────────────┘
         │ alerts (1 partition)
         ▼
┌──────────────────────────────┐
│  Alert Storage Service       │  Micro-batch buffer → Elasticsearch _bulk
│  (Python asyncio)            │  _id = alert_id → idempotent upsert (ADR-0014)
│  Flush: size ≥ 500 OR 5 s   │
└──────────────┬───────────────┘
               ▼
┌──────────────────────┐
│  Elasticsearch       │  Index: alerts  (alert_id, rule_id, host → keyword)
│  (single-node)       │
└──────────────────────┘
```

### Kafka Topics

| Topic | Partitions | Key | Purpose |
|---|---|---|---|
| `raw-logs` | 8 | `host` field (UTF-8) | Raw Log stream; all events from the same host always route to the same partition |
| `alerts` | 1 | — | Matched Alert stream consumed by Alert Storage |
| `rule-updates` | 1 | — | Typed JSON envelopes for add/update/delete rule lifecycle operations; fan-out to all workers |

### Rule Engine Concurrency

Each worker process is assigned one or more partitions of `raw-logs` by Kafka's consumer-group rebalancer. Partition count is 8; any replica count from 1–8 is valid — Kafka distributes partitions automatically. Because `raw-logs` is keyed by host, all events from the same machine always arrive at the same worker, making per-worker in-memory sliding windows correct without any cross-worker coordination (ADR-0010).

For `rule-updates`, each worker uses a **unique consumer group ID** (derived from its `WORKER_ID`) so that every worker receives every rule envelope — fan-out, not competing consumption.

### Sigma Rule Support

The Rule Engine implements its own YAML-to-condition parser supporting:

- **Field equality:** `event_id: '4625'`
- **String modifiers:** `field|contains`, `field|startswith`, `field|endswith`
- **List values (OR):** `event_id: ['4624', '4625', '4648']`
- **Boolean logic:** `and`, `or`, `not`, parenthesised expressions
- **Aggregation (time-window):** `selection | count() by host > N` with a `timeframe: <N>s` key — evaluated via a per-worker `SlidingWindow`

### Log Generator State Machine

The Log Generator runs a per-host state machine (ADR-0016) that produces correlated attack sequences rather than purely random events:

| State | Emitted events |
|---|---|
| `idle` | Random mix — baseline noise |
| `brute_forcing` | Rapid `event_id 4625` (failed login) bursts |
| `compromised` | `event_id 4624` (successful login) → `event_id 4672` (privilege use) |
| `lateral_moving` | `event_id 4688` (process creation) with suspicious `process_name` |

Transition probabilities are weighted-random, so hosts cycle through attack phases organically. The runtime EPS rate can be changed without restarting the container via the HTTP admin endpoint.

---

## Project Structure

```
kafka-sigma-engine/
├── docker-compose.yml          # Full stack: Kafka, ES, Prometheus, Grafana, services
├── pyproject.toml              # Project metadata, pytest config, mypy config
├── requirements.txt            # Pinned runtime dependencies
│
├── k8s/                        # Kubernetes manifests (minikube)
│   ├── namespace.yaml
│   ├── kafka/
│   │   └── values.yaml         # Bitnami Helm chart values (8 partitions, KRaft)
│   ├── elasticsearch/
│   ├── prometheus/             # Includes kubernetes_sd_configs for Rule Engine pods
│   ├── grafana/
│   ├── rule-engine/            # Deployment (replicas: 8) + headless Service
│   ├── alert-storage/
│   └── log-generator/         # Deployment + LoadBalancer Service (port 8080)
│
├── prometheus/
│   └── prometheus.yml          # Scrape config for Docker Compose stack
│
├── grafana/
│   ├── dashboards/
│   │   └── sigma_engine.json   # Pre-built dashboard: EPS, p99 latency, consumer lag
│   └── provisioning/
│
├── services/                   # One Dockerfile per microservice
│   ├── alert_storage/
│   ├── log_generator/
│   └── rule_engine/
│
├── sigma_rules/                # Bundled Sigma Rule YAML files (loaded at startup)
│   ├── windows_failed_login.yml           # event_id 4625 → medium
│   ├── windows_successful_login.yml       # event_id 4624 → low
│   ├── windows_explicit_credentials_logon.yml  # event_id 4648 → medium
│   ├── windows_privilege_use.yml          # event_id 4672 → high
│   ├── windows_suspicious_process.yml     # event_id 4688 + process_name|contains → medium
│   ├── windows_brute_force.yml            # aggregation: >5 × 4625 within 60 s → high
│   ├── cloudtrail_bucket_delete.yml       # action startswith DeleteBucket → high
│   └── cloudtrail_iam_user_create.yml     # action = CreateUser → high
│
├── src/
│   ├── exceptions.py           # Domain exception types
│   ├── models.py               # SigmaRule, Alert dataclasses
│   ├── alert_storage/
│   │   ├── main.py             # Service entry point; _ESIndexer sets _id=alert_id
│   │   └── service.py          # AlertStorageService: micro-batch buffer + flush logic
│   ├── log_generator/
│   │   ├── __main__.py         # Entry point; wires HostStateMachine + admin server
│   │   ├── generator.py        # generate_raw_log() + HostStateMachine (state machine)
│   │   ├── admin.py            # LogAdminHandler: GET/POST /rate (ADR-0015)
│   │   └── service.py          # LogGeneratorService: async publish loop + EPS control
│   └── rule_engine/
│       ├── main.py             # Entry point: raw-logs consumer + rule-updates fan-out
│       ├── evaluator.py        # evaluate(raw_log, rules) → list[Alert] (single-log)
│       ├── loader.py           # load_rules(path) → list[SigmaRule]
│       ├── service.py          # RuleEngineService: rule set management + evaluate_log()
│       └── window.py           # SlidingWindow: per-host time-window event counter
│
└── tests/
    ├── conftest.py
    ├── integration/            # Live-stack tests (Docker Compose or minikube)
    │   └── test_pipeline.py
    └── unit/
        ├── test_alert_storage.py
        ├── test_log_generator.py
        ├── test_models.py
        ├── test_rule_engine.py
        └── test_rule_engine_service.py
```

---

## Getting Started — Docker Compose

Docker Compose is the fast inner-loop development environment. Use it for rule authoring, local debugging, and running the test suite.

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin)
- Python 3.11+ (for running tests locally)

### 1. Clone the repository

```bash
git clone git@github.com:ChengenHsieh0225/kafka-sigma-engine.git
cd kafka-sigma-engine
```

### 2. Spin up the full stack

This starts Kafka (KRaft mode), Elasticsearch, Prometheus, Grafana, four Rule Engine workers, the Alert Storage Service, and the Log Generator. The `--wait` flag blocks until every service with a health check reports healthy.

```bash
docker compose --profile load up -d --wait
```

> **Note:** Always pass `--profile load` in every `docker compose` command for this project (including `down`, `logs`, `ps`). Starting the core stack without the profile and adding the Log Generator in a second command causes a Docker network reconnection failure.

Expected healthy services: `kafka`, `elasticsearch`, `prometheus`, `grafana`, `rule-engine-1..4`, `alert-storage`, `log-generator`.

### 3. Verify Kafka topics

```bash
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --list
# alerts
# raw-logs
# rule-updates
```

### 4. Verify end-to-end flow

```bash
# Total alert count
curl -s "http://localhost:9200/alerts/_count" | python3 -m json.tool

# Sample alert document
curl -s "http://localhost:9200/alerts/_search?size=1" | python3 -m json.tool
```

### 5. Adjust Log Generator rate at runtime

The Log Generator exposes an HTTP admin endpoint. Change EPS without restarting:

```bash
# Set rate to 5000 EPS
curl -s -X POST http://localhost:8080/rate \
  -H "Content-Type: application/json" \
  -d '{"eps": 5000}'

# Check current rate
curl -s http://localhost:8080/rate
```

### 6. Manage rules at runtime (hot-reload)

Rules can be added, updated, or deleted while the pipeline is running. Publish a typed JSON envelope to the `rule-updates` topic — all workers apply the change without restart.

**Add a new rule:**
```bash
echo '{"op":"add","rule_id":"win-rdp-001","rule":{"id":"win-rdp-001","title":"RDP Logon","level":"medium","detection":{"sel":{"log_type":"windows_event","event_id":"4624"},"condition":"sel"}}}' | \
  docker compose exec -T kafka /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic rule-updates
```

**Delete a rule:**
```bash
echo '{"op":"delete","rule_id":"win-rdp-001"}' | \
  docker compose exec -T kafka /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic rule-updates
```

**Update a rule** — publish an `"op":"update"` envelope with the same `rule_id` and the updated rule body.

### 7. Tear down

```bash
docker compose --profile load down
```

> If you see a `network not found` error, run `docker compose --profile load down` followed by `docker compose --profile load up -d --wait` to recover.

---

## Getting Started — Kubernetes (minikube)

The `k8s/` directory deploys the full stack on minikube with the Rule Engine running as 8 replicas. Use this environment for load testing and scaling demos.

### Prerequisites

- [minikube](https://minikube.sigs.k8s.io/docs/start/) with Docker driver
- [Helm](https://helm.sh/docs/intro/install/) (for the Kafka chart)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)

### 1. Start minikube

```bash
minikube start --driver=docker --cpus=4 --memory=8g
```

### 2. Point Docker to minikube's daemon and build images

```bash
eval $(minikube docker-env)
docker build -t kafka-sigma-engine/rule-engine:latest -f services/rule_engine/Dockerfile .
docker build -t kafka-sigma-engine/alert-storage:latest -f services/alert_storage/Dockerfile .
docker build -t kafka-sigma-engine/log-generator:latest -f services/log_generator/Dockerfile .
```

### 3. Deploy Kafka via Helm

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install kafka bitnami/kafka \
  --namespace kafka-sigma-engine \
  --create-namespace \
  --values k8s/kafka/values.yaml
```

### 4. Deploy the rest of the stack

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/elasticsearch/
kubectl apply -f k8s/prometheus/
kubectl apply -f k8s/grafana/
kubectl apply -f k8s/rule-engine/
kubectl apply -f k8s/alert-storage/
kubectl apply -f k8s/log-generator/
```

Wait for all pods to reach Running:

```bash
kubectl get pods -n kafka-sigma-engine --watch
```

### 5. Access dashboards

```bash
minikube tunnel   # Keep running in a separate terminal
```

Then open:
- **Grafana:** `http://$(minikube service grafana -n kafka-sigma-engine --url)`
- **Prometheus:** `http://$(minikube service prometheus -n kafka-sigma-engine --url)`
- **minikube dashboard:** `minikube dashboard`

### 6. Scale the Rule Engine

```bash
# Scale up to 8 replicas (max — matches 8 partitions)
kubectl scale deployment rule-engine -n kafka-sigma-engine --replicas=8

# Scale down — Kafka redistributes partitions automatically
kubectl scale deployment rule-engine -n kafka-sigma-engine --replicas=4
```

### 7. Adjust Log Generator rate via K8s

```bash
LOG_GEN_URL=$(minikube service log-generator -n kafka-sigma-engine --url)
curl -X POST "$LOG_GEN_URL/rate" -H "Content-Type: application/json" -d '{"eps": 5000}'
curl "$LOG_GEN_URL/rate"
```

### 8. Run integration tests against minikube

Kafka advertises its internal pod hostname in metadata responses. Add it to `/etc/hosts` so it resolves through the port-forward tunnel (one-time setup per machine):

```bash
echo "127.0.0.1 kafka-controller-0.kafka-controller-headless.kafka-sigma-engine.svc.cluster.local" \
  | sudo tee -a /etc/hosts
```

Forward Kafka and Elasticsearch to localhost. Skip if already running (check with `lsof -ti tcp:9092`):

```bash
kubectl port-forward -n kafka-sigma-engine svc/kafka 9092:9092 &
kubectl port-forward -n kafka-sigma-engine svc/elasticsearch 9200:9200 &
```

Run the suite:

```bash
pytest -m integration tests/integration/
```

---

## Configuration

All services are configured through environment variables. The defaults below match `docker-compose.yml`.

### Log Generator

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Kafka broker address |
| `LOG_GENERATOR_TOPIC` | `raw-logs` | Target Kafka topic |
| `LOG_GENERATOR_EPS` | `1000` | Initial events per second (adjustable at runtime via `POST /rate`) |
| `LOG_GENERATOR_ADMIN_PORT` | `8080` | Port for the `GET /rate` and `POST /rate` HTTP admin endpoint |

The Log Generator always uses the per-host state machine. Initial EPS is set by `LOG_GENERATOR_EPS`; use `POST /rate` to change it without a restart.

### Rule Engine (per worker)

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Kafka broker address |
| `SIGMA_RULES_DIR` | `sigma_rules` | Directory scanned for `*.yml` Sigma Rules on startup |
| `METRICS_PORT` | `8001` | Port for the Prometheus `/metrics` HTTP endpoint |
| `WORKER_ID` | *(random UUID)* | Unique identifier; used to derive a unique `rule-updates` consumer group ID |

### Alert Storage Service

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Kafka broker address |
| `ELASTICSEARCH_URL` | `http://elasticsearch:9200` | Elasticsearch endpoint |
| `BATCH_SIZE` | `500` | Flush the micro-batch buffer when this many Alerts are buffered |
| `FLUSH_INTERVAL` | `5` | Flush the buffer when this many seconds have elapsed since the last flush |

---

## Testing Guide

### Install development dependencies

```bash
pip install -e ".[dev]"
```

### Unit tests

Unit tests have no external dependencies and run without Docker or Kubernetes. They cover `evaluate()`, `RuleEngineService` (rule lifecycle + windowed evaluation), `SlidingWindow`, `AlertStorageService` (micro-batch + injected clock), `HostStateMachine`, and `LogAdminHandler`.

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

Integration tests run against a live stack and exercise the full Kafka → Rule Engine → Elasticsearch path. They use real Kafka and Elasticsearch connections — no mocking of external clients.

**Against Docker Compose:**

```bash
docker compose --profile load up -d --wait
pytest -m integration tests/integration/
```

**Against minikube:**

Kafka advertises its internal cluster hostname in metadata responses. Before port-forwarding works end-to-end, add that hostname to your `/etc/hosts` so it resolves back through the tunnel:

```bash
echo "127.0.0.1 kafka-controller-0.kafka-controller-headless.kafka-sigma-engine.svc.cluster.local" \
  | sudo tee -a /etc/hosts
```

Then forward the ports (skip if already running — check with `lsof -ti tcp:9092`):

```bash
kubectl port-forward -n kafka-sigma-engine svc/kafka 9092:9092 &
kubectl port-forward -n kafka-sigma-engine svc/elasticsearch 9200:9200 &
```

Run the suite:

```bash
pytest -m integration tests/integration/
```

Both `KAFKA_BOOTSTRAP` and `ES_URL` can be overridden via environment variables if you use a different bootstrap address (e.g. NodePort):

```bash
KAFKA_BOOTSTRAP=$(minikube ip):30092 ES_URL=http://localhost:9200 pytest -m integration tests/integration/
```

The integration suite verifies:

| Test | What it checks |
|---|---|
| `test_windows_failed_login_creates_alert_in_elasticsearch` | Basic end-to-end path: raw log → Rule Engine → ES |
| `test_cloudtrail_bucket_delete_creates_alert_in_elasticsearch` | `startswith` string modifier |
| `test_non_matching_log_produces_no_alert` | No false positives |
| `test_duplicate_alert_message_is_deduplicated_in_elasticsearch` | `_id=alert_id` idempotent upsert |
| `test_rule_update_add_envelope_creates_alert` | Typed JSON envelope hot-reload (add) |
| `test_windows_successful_login_creates_alert` | `event_id 4624` rule |
| `test_windows_explicit_credentials_creates_alert` | `event_id 4648` rule |
| `test_windows_privilege_use_creates_alert` | `event_id 4672` rule |
| `test_windows_suspicious_process_creates_alert` | `event_id 4688` + `process_name\|contains` |
| `test_cloudtrail_iam_user_create_creates_alert` | CloudTrail CreateUser rule |
| `test_brute_force_aggregation_rule_creates_alert` | Sliding-window aggregation (>5 events / 60 s) |

To exclude integration tests during local development:

```bash
pytest -m "not integration" tests/
```

---

## Observability

### Grafana — `http://localhost:3000`

The Grafana dashboard is provisioned automatically on startup (no login required). Navigate to **Dashboards → Sigma Engine**.

| Panel | Metric | What it shows |
|---|---|---|
| **EPS Throughput** | `rate(logs_processed_total[1m])` summed across workers | Real-time events per second processed by the Rule Engine |
| **p99 Matching Latency** | `histogram_quantile(0.99, rule_evaluation_duration_seconds_bucket)` | 99th-percentile time to evaluate one Raw Log against all loaded rules |
| **Consumer Lag** | `kafka_consumer_lag` per worker | Backlog of unprocessed messages; spikes indicate the Rule Engine is falling behind the Log Generator |

In Kubernetes, Prometheus uses `kubernetes_sd_configs` to auto-discover all Rule Engine pods — no static target list is required. All replicas appear automatically as scrape targets.

### Prometheus — `http://localhost:9090`

Verify all Rule Engine scrape targets are active:

```
http://localhost:9090/targets
```

### Elasticsearch — `http://localhost:9200`

| Query | Description |
|---|---|
| `GET /alerts/_count` | Total Alert documents indexed |
| `GET /alerts/_search?q=severity:high` | High-severity alerts |
| `GET /alerts/_search?q=rule_id:win-brute-force-001` | Brute-force aggregation alerts |
| `GET /alerts/_search?q=alert_id:<id>` | Exactly one document per `alert_id` (deduplication) |

The `alert_id`, `severity`, `rule_id`, and `host` fields are indexed as `keyword`, enabling exact-match filtering and bucket aggregations.

### Bundled Sigma Rules

Eight rules ship with the repository and are loaded on startup by every Rule Engine worker:

| File | Rule ID | Trigger condition | Severity |
|---|---|---|---|
| `windows_failed_login.yml` | `win-failed-login-001` | `event_id = 4625` (failed login) | `medium` |
| `windows_successful_login.yml` | `win-successful-login-001` | `event_id = 4624` (successful login) | `low` |
| `windows_explicit_credentials_logon.yml` | `win-explicit-creds-001` | `event_id = 4648` (explicit credential use) | `medium` |
| `windows_privilege_use.yml` | `win-privilege-use-001` | `event_id = 4672` (special privilege assigned) | `high` |
| `windows_suspicious_process.yml` | `win-suspicious-process-001` | `event_id = 4688` AND `process_name` contains `powershell` or `cmd` | `medium` |
| `windows_brute_force.yml` | `win-brute-force-001` | `event_id = 4625` more than 5 times within 60 s from same host | `high` |
| `cloudtrail_bucket_delete.yml` | `aws-s3-delete-001` | `action` starts with `DeleteBucket` | `high` |
| `cloudtrail_iam_user_create.yml` | `aws-iam-create-user-001` | `action = CreateUser` | `high` |

Add new rules by placing `.yml` files in `sigma_rules/` and restarting the workers, or deliver them live with a `{"op":"add", ...}` envelope on the `rule-updates` topic.

---

## Key Engineering Decisions

Full rationale is recorded in `docs/adr/`:

| ADR | Decision |
|---|---|
| `0001` | Kafka `rule-updates` topic for Sigma Rule delivery (vs. REST API or file-watcher) |
| `0002` | Python asyncio for the Rule Engine (vs. Go) |
| `0003` | Multiple independent asyncio processes as the worker pool (vs. `ProcessPoolExecutor`) |
| `0004` | Elasticsearch for Alert storage (vs. PostgreSQL) |
| `0005` | `raw-logs`: originally 4 partitions, keyed by host — superseded by ADR-0012 |
| `0006` | Manual at-least-once offset commits (vs. auto-commit or exactly-once) |
| `0007` | Dual flush triggers: size ≥ 500 OR elapsed ≥ 5 s |
| `0008` | Alert documents embed the full Raw Log (vs. reference by offset) |
| `0009` | Prometheus + Grafana for observability |
| `0010` | In-memory sliding window per worker for aggregation rules (vs. Redis-backed shared counter) |
| `0011` | Typed JSON envelope for rule lifecycle operations — add, update, delete (supersedes bare-YAML add-only) |
| `0012` | `raw-logs` topic increased to 8 partitions for Kubernetes horizontal scaling (supersedes ADR-0005) |
| `0013` | Full Kubernetes stack in `k8s/` using minikube (vs. hybrid Docker Compose + K8s) |
| `0014` | Alert deduplication via Elasticsearch `_id = alert_id` (vs. query-time collapse or in-memory set) |
| `0015` | Log Generator HTTP admin endpoint for runtime EPS adjustment (vs. Kafka control topic or signals) |
| `0016` | Per-host state machine in Log Generator for correlated attack sequences (vs. YAML scenario playbook) |
