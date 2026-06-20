# In-Memory Sliding Window for Time-Window Aggregation Rules

Per-host time-window aggregation rules (e.g. "event_id 4625 more than 5 times within 60 seconds from the same host") use an in-memory sliding window maintained by each Rule Engine worker process, rather than a Redis-backed shared counter.

This is sound because `raw-logs` is partitioned by `host` (ADR-0005), guaranteeing that all events from the same host are always routed to the same worker. A per-worker in-memory window therefore captures every event for any given host without cross-worker coordination.

Redis was rejected because: it adds a new infrastructure dependency and network round-trips in the hot matching path; it is unnecessary for per-host rules given the existing host-key partitioning guarantee; and cross-host aggregation is not a stated requirement.

## Consequences

- Window state is lost when a worker restarts. Re-detecting a burst that was interrupted by a restart is accepted as the cost of this simplicity.
- Replica count in Kubernetes must always be ≤ partition count so that host-key affinity is preserved. If replicas < partitions, Kafka reassigns multiple partitions to one replica; all events for those hosts still flow to a single worker, so in-memory windows remain correct.
- Cross-host aggregation rules cannot be expressed with this approach. If that requirement emerges, Redis can be introduced at that point.
