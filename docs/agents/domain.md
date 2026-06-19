# Domain Docs

Single-context repo. One `CONTEXT.md` at the repo root; ADRs in `docs/adr/`.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — domain glossary (detection and pipeline terms)
- **`docs/adr/`** — nine ADRs covering Sigma Rule scope, Rule Engine language and concurrency, storage backend, Kafka topology, offset commit strategy, micro-batch flush triggers, Alert schema, Raw Log schema, and observability stack

## File structure

```
/
├── CONTEXT.md
├── docs/
│   ├── adr/
│   │   ├── 0001-kafka-rule-updates-topic-for-rule-delivery.md
│   │   ├── 0002-python-asyncio-for-rule-engine.md
│   │   ├── 0003-multiple-asyncio-processes-as-consumer-group.md
│   │   ├── 0004-elasticsearch-for-alert-storage.md
│   │   ├── 0005-raw-logs-topic-4-partitions-host-key.md
│   │   ├── 0006-at-least-once-offset-commit.md
│   │   ├── 0007-micro-batch-dual-flush-triggers.md
│   │   ├── 0008-alert-embeds-full-raw-log.md
│   │   └── 0009-prometheus-grafana-observability.md
│   └── agents/
└── src/
```

## Use the glossary's vocabulary

Use terms exactly as defined in `CONTEXT.md`. Key terms: Raw Log, Sigma Rule, Alert, Rule Lifecycle, Ingestion Pipeline, Micro-Batching.
