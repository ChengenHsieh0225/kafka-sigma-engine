# Prometheus + Grafana for Observability

Prometheus and Grafana are added to the Docker Compose stack to measure and visualize the three key portfolio metrics. Each Python service exposes a `/metrics` endpoint via `prometheus_client`. Console-only logging was rejected because a throughput graph is substantially more convincing to a portfolio reviewer than terminal output.

## Instrumentation targets

| Metric | Instrument | What it proves |
|---|---|---|
| `logs_processed_total` (per process) | Counter | EPS throughput via `rate()` |
| `rule_evaluation_duration_seconds` | Histogram | p99 matching latency |
| `kafka_consumer_lag` | Gauge | Fault tolerance / backpressure signal |
