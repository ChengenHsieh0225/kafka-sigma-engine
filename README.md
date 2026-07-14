# Kafka Sigma Engine

A horizontally-scalable log ingestion and threat detection pipeline that simulates a cloud-native XDR (Extended Detection and Response) platform. The system ingests synthetic security events, evaluates them in real time against [Sigma](https://github.com/SigmaHQ/sigma) detection rules using a horizontally-scaled worker pool, and persists matching Alerts to Elasticsearch — all observable through a live Grafana dashboard. Sustained throughput on a 4-CPU minikube instance reaches ≥ 10,000 EPS with no lag growth over a sustained 5-minute run; higher rates were not explored on this hardware.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture & Data Flow](#architecture--data-flow)
- [Project Structure](#project-structure)
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
| Kubernetes deployment | Full stack in `k8s/` targeting minikube; Rule Engine runs 4 replicas by default, scales up to 8 (matching partition count) with `kubectl scale` |

**Measured performance (4-CPU / 8 GB minikube, 4 Rule Engine replicas — the default):**

| Metric | Measured | Notes |
|---|---|---|
| Sustained throughput | **≥ 10,000 EPS** | Verified at the 4-replica default: 3 min each at 5,000 and 10,000 EPS, consumer lag stable with no growth trend. Also verified at the 8-replica maximum in a longer run (5 min each at 7,500 and 10,000 EPS). Testing was capped at 10,000 EPS by design — the ceiling on this hardware wasn't explored further |
| Per-event rule evaluation | sub-millisecond | 8 rules, pure Python, no I/O |
| Log loss on worker restart | zero | at-least-once commits; duplicates deduplicated by `alert_id` |

Throughput is achieved by fire-and-forget alert publishing (`producer.send()`) and batched consumer offset commits (every 100 messages or 5 s). Kubernetes `requests`/`limits` for every workload are sized against `metrics-server`-measured real usage rather than estimates — see ADR-0017 for the methodology and the resource-budget trade-off behind the 4-replica default.

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
├── CONTEXT.md                  # Single-context domain doc: data flow, glossary, constraints
├── pyproject.toml              # Project metadata, pytest config, mypy config
├── requirements.txt            # Pinned runtime dependencies
│
├── docs/
│   ├── adr/                    # Architecture Decision Records (ADR-0001 … ADR-0016)
│   └── agents/                 # Agent skill docs: issue-tracker, triage-labels, domain
│
├── k8s/                        # Kubernetes manifests (minikube)
│   ├── namespace.yaml
│   ├── kafka/
│   │   ├── kafka.yaml          # Apache Kafka 3.8.1 StatefulSet, Services, topic-provisioning Job
│   │   └── values.yaml         # Legacy Bitnami Helm chart values (reference only)
│   ├── elasticsearch/          # Deployment + ClusterIP Service
│   ├── prometheus/             # Deployment, Service, ConfigMap, RBAC for kubernetes_sd_configs
│   ├── grafana/                # Deployment, Service, ConfigMaps (datasource, dashboard provider, dashboard JSON)
│   ├── rule-engine/            # Deployment + headless Service
│   ├── alert-storage/          # Deployment
│   └── log-generator/         # Deployment + LoadBalancer Service (port 8080)
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
    ├── integration/
    │   └── test_pipeline.py    # 11 end-to-end tests against the live minikube stack
    └── unit/
        ├── test_aggregation_rule.py        # SlidingWindow + brute-force rule evaluation
        ├── test_alert_storage.py           # AlertStorageService: micro-batch + flush logic
        ├── test_k8s_manifests.py           # Smoke-checks on k8s YAML structure
        ├── test_log_generator.py           # LogGeneratorService: publish loop + EPS control
        ├── test_log_generator_admin.py     # LogAdminHandler: GET/POST /rate
        ├── test_log_generator_state_machine.py  # HostStateMachine state transitions
        ├── test_models.py                  # SigmaRule, Alert dataclasses
        ├── test_rule_engine.py             # evaluate(): field equality, modifiers, boolean logic
        ├── test_rule_engine_service.py     # RuleEngineService: rule lifecycle + evaluate_log()
        ├── test_sigma_rules.py             # All bundled .yml rules parse and match correctly
        └── test_window.py                  # SlidingWindow: eviction, threshold, edge cases
```

---

## Getting Started — Kubernetes (minikube)

The `k8s/` directory deploys the full stack on minikube with the Rule Engine running as 4 replicas by default (scales up to 8, matching the `raw-logs` partition count — see [Scale the Rule Engine](#7-scale-the-rule-engine)).

### Prerequisites

- [minikube](https://minikube.sigs.k8s.io/docs/start/) with Docker driver
- [kubectl](https://kubernetes.io/docs/tasks/tools/)

### 1. Clone the repository

```bash
git clone git@github.com:ChengenHsieh0225/kafka-sigma-engine.git
cd kafka-sigma-engine
```

### 2. Start minikube

```bash
minikube start --driver=docker --cpus=4 --memory=8g
```

### 3. Point Docker to minikube's daemon and build images

```bash
eval $(minikube docker-env)
docker build -t kafka-sigma-engine/rule-engine:latest -f services/rule_engine/Dockerfile .
docker build -t kafka-sigma-engine/alert-storage:latest -f services/alert_storage/Dockerfile .
docker build -t kafka-sigma-engine/log-generator:latest -f services/log_generator/Dockerfile .
```

### 4. Deploy Kafka

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/kafka/kafka.yaml
```

Wait for Kafka to be ready and for the topic-provisioning Job to complete:

```bash
kubectl wait --for=condition=ready pod/kafka-controller-0 -n kafka-sigma-engine --timeout=120s
kubectl wait --for=condition=complete job/kafka-topic-provisioning -n kafka-sigma-engine --timeout=120s
```

### 5. Deploy the rest of the stack

```bash
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

### 6. Access dashboards

```bash
minikube tunnel   # Keep running in a separate terminal
```

Get each service URL and open it in your browser:

```bash
minikube service grafana -n kafka-sigma-engine --url      # Grafana
minikube service prometheus -n kafka-sigma-engine --url   # Prometheus
```

- **minikube dashboard:** `minikube dashboard` — then switch the namespace dropdown (top-left) from **default** to **kafka-sigma-engine** to see pods

### 7. Scale the Rule Engine

The default is 4 replicas — sized to leave Kafka enough of the node's CPU budget (ADR-0017). Scale up to demonstrate the full horizontal-scaling story:

```bash
# Scale up to 8 replicas (max — matches 8 partitions)
kubectl scale deployment rule-engine -n kafka-sigma-engine --replicas=8

# Scale back down to the default — Kafka redistributes partitions automatically
kubectl scale deployment rule-engine -n kafka-sigma-engine --replicas=4
```

### 8. Adjust Log Generator rate

```bash
LOG_GEN_URL=$(minikube service log-generator -n kafka-sigma-engine --url)
curl -X POST "$LOG_GEN_URL/rate" -H "Content-Type: application/json" -d '{"eps": 5000}'
curl "$LOG_GEN_URL/rate"
```

### 9. Manage rules at runtime (hot-reload)

Rules can be added, updated, or deleted while the pipeline is running. Publish a typed JSON envelope to the `rule-updates` topic — all workers apply the change without restart.

**Add a new rule:**
```bash
kubectl exec -n kafka-sigma-engine kafka-controller-0 -- \
  /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic rule-updates <<'EOF'
{"op":"add","rule_id":"win-rdp-001","rule":{"id":"win-rdp-001","title":"RDP Logon","level":"medium","detection":{"sel":{"log_type":"windows_event","event_id":"4624"},"condition":"sel"}}}
EOF
```

**Delete a rule:**
```bash
kubectl exec -n kafka-sigma-engine kafka-controller-0 -- \
  /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server localhost:9092 \
    --topic rule-updates <<'EOF'
{"op":"delete","rule_id":"win-rdp-001"}
EOF
```

**Update a rule** — publish an `"op":"update"` envelope with the same `rule_id` and the updated rule body.

### 10. Run integration tests

Kafka advertises its internal pod hostname in metadata responses. Add it to `/etc/hosts` so it resolves through the port-forward tunnel (one-time setup per machine):

```bash
echo "127.0.0.1 kafka-controller-0.kafka-controller-headless.kafka-sigma-engine.svc.cluster.local" \
  | sudo tee -a /etc/hosts
```

Scale the Log Generator to 0 before running tests. At 1000 EPS it floods the `raw-logs` partitions — test messages get buried in the backlog and time out:

```bash
kubectl scale deployment log-generator -n kafka-sigma-engine --replicas=0
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

Restore the Log Generator when done:

```bash
kubectl scale deployment log-generator -n kafka-sigma-engine --replicas=1
```

> **If tests still time out** after scaling down the Log Generator, the `rule-engine` consumer group may have stale offsets from a previous run — the backlog can be millions of messages deep. Reset the offsets to skip it (scale to 0 first, wait ~30 s for the group to go inactive, then reset):
> ```bash
> kubectl scale deployment rule-engine -n kafka-sigma-engine --replicas=0
> # wait ~30 s
> kubectl exec -n kafka-sigma-engine kafka-controller-0 -- \
>   /opt/kafka/bin/kafka-consumer-groups.sh \
>     --bootstrap-server localhost:9092 \
>     --group rule-engine --reset-offsets --to-latest --all-topics --execute
> kubectl scale deployment rule-engine -n kafka-sigma-engine --replicas=4
> ```

---

## Configuration

All services are configured through environment variables.

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
| `COMMIT_EVERY_N` | `100` | Commit consumer offsets after this many messages (whichever threshold is reached first) |
| `COMMIT_EVERY_S` | `5.0` | Commit consumer offsets after this many seconds since the last commit |

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

Unit tests have no external dependencies and run without Kubernetes. They cover `evaluate()`, `RuleEngineService` (rule lifecycle + windowed evaluation), `SlidingWindow`, `AlertStorageService` (micro-batch + injected clock), `HostStateMachine`, and `LogAdminHandler`.

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

Integration tests run against the live minikube stack and exercise the full Kafka → Rule Engine → Elasticsearch path. They use real Kafka and Elasticsearch connections — no mocking of external clients.

Kafka advertises its internal cluster hostname in metadata responses. Before port-forwarding works end-to-end, add that hostname to your `/etc/hosts` so it resolves back through the tunnel:

```bash
echo "127.0.0.1 kafka-controller-0.kafka-controller-headless.kafka-sigma-engine.svc.cluster.local" \
  | sudo tee -a /etc/hosts
```

Scale the Log Generator to 0 replicas before running the suite — its 1000 EPS flood buries test messages in the partition backlog and causes timeouts:

```bash
kubectl scale deployment log-generator -n kafka-sigma-engine --replicas=0
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

Restore the Log Generator when done:

```bash
kubectl scale deployment log-generator -n kafka-sigma-engine --replicas=1
```

> **If tests still time out**, the consumer group has a stale backlog from a previous session. See the [offset-reset note](#10-run-integration-tests) in the Getting Started guide.

Both `KAFKA_BOOTSTRAP` and `ES_URL` can be overridden if the port-forward addresses differ:

```bash
KAFKA_BOOTSTRAP=localhost:9092 ES_URL=http://localhost:9200 pytest -m integration tests/integration/
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

To exclude integration tests:

```bash
pytest -m "not integration" tests/
```

---

## Observability

Services are accessed via `minikube service` (Grafana, Prometheus) or `kubectl port-forward` (Elasticsearch). Run `minikube tunnel` in a separate terminal first so LoadBalancer IPs are assigned.

### Grafana

```bash
minikube service grafana -n kafka-sigma-engine --url
```

Copy the printed URL into your browser. The dashboard is provisioned automatically on startup (no login required). Navigate to **Dashboards → Kafka Sigma Engine**.

| Panel | Metric | What it shows |
|---|---|---|
| **EPS Throughput** | `rate(logs_processed_total[1m])` summed across workers | Real-time events per second processed by the Rule Engine |
| **p99 Matching Latency** | `histogram_quantile(0.99, rule_evaluation_duration_seconds_bucket)` | 99th-percentile time to evaluate one Raw Log against all loaded rules |
| **Consumer Lag** | `kafka_consumer_lag` per pod | Backlog of unprocessed messages; spikes indicate the Rule Engine is falling behind the Log Generator |

Prometheus uses `kubernetes_sd_configs` to auto-discover all Rule Engine pods — all replicas appear as scrape targets without any static configuration.

### Prometheus

```bash
minikube service prometheus -n kafka-sigma-engine --url
```

Copy the printed URL into your browser. Verify all Rule Engine scrape targets are active at **Status → Targets** (the expression browser on the home page shows "No data queried yet" until you enter a PromQL query — that is normal).

### Elasticsearch

Elasticsearch has a ClusterIP service and is not exposed externally. Access it via port-forward:

```bash
kubectl port-forward -n kafka-sigma-engine svc/elasticsearch 9200:9200 &
```

Then query at `http://localhost:9200`:

| Query | Description |
|---|---|
| `GET /alerts/_count` | Total Alert documents indexed |
| `GET /alerts/_search?q=severity:high` | High-severity alerts |
| `GET /alerts/_search?q=rule_id:win-brute-force-001` | Brute-force aggregation alerts |
| `GET /alerts/_search?q=alert_id:<id>` | Exactly one document per `alert_id` (deduplication) |

The `alert_id`, `severity`, `rule_id`, and `host` fields are indexed as `keyword`, enabling exact-match filtering and bucket aggregations.

### Resource usage (`kubectl top`)

Prometheus and Grafana surface application metrics; neither reports actual container CPU/memory usage. For that, enable the `metrics-server` addon:

```bash
minikube addons enable metrics-server
kubectl top pods -n kafka-sigma-engine
```

This is what every `resources.requests`/`limits` value in `k8s/` is sized against (ADR-0017) — real measured usage under load, not estimates. `kubectl top` only reports a live snapshot (no history), so re-measure after any load-shape change rather than trusting old numbers.

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
| `0017` | Rule Engine default replicas reduced 8 → 4, freeing CPU budget for Kafka on a 4-CPU minikube target (supersedes the `replicas: 8` default in ADR-0012/ADR-0013; 8 remains the max) |
