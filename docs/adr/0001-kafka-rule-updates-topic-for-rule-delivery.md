# Kafka `rule-updates` Topic for Sigma Rule Delivery

New Sigma Rules authored by Information Security Engineers are published to a dedicated Kafka topic (`rule-updates`) and consumed by the Rule Engine at runtime. This keeps rule delivery consistent with the Kafka-native architecture, provides an automatic audit trail via Kafka's log retention, and avoids coupling the Rule Engine to a shared filesystem or requiring it to expose an HTTP server. Delivery is scoped to add-only; rule updates and deletes are deferred to avoid in-flight evaluation consistency issues.

## Considered Options

- **File-watcher on a shared volume** — simpler, but requires a shared filesystem and doesn't fit a distributed container-based deployment.
- **REST/gRPC endpoint on the Rule Engine** — clean interface, but adds an HTTP server to a service whose sole job is stream processing.
- **Restart-based deployment** — no implementation cost, but hot-reload is not a feature.
