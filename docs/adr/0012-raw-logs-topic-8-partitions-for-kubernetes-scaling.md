# `raw-logs` Topic Increased to 8 Partitions for Kubernetes Scaling

The `raw-logs` Kafka topic partition count is increased from 4 (ADR-0005) to 8 to support horizontal scaling of the Rule Engine in Kubernetes up to 8 simultaneous pod replicas. This doubles the maximum useful Rule Engine parallelism while remaining comfortable on a laptop-class local Kubernetes cluster (minikube or kind).

16 partitions was rejected: 16 Rule Engine pods under load testing would likely exhaust local cluster CPU/memory before meaningful Kafka throughput numbers are reached, producing a worse observability story rather than a better one.

## Consequences

- Adding partitions changes the host → partition hash mapping. Any in-progress in-memory sliding-window state (ADR-0010) held by existing workers is silently reset on repartition. This is acceptable as long as repartitioning occurs before time-window aggregation rules go live.
- The Rule Engine Kubernetes Deployment should be configured with `replicas: 8` as the maximum. Setting fewer replicas is valid; Kafka will assign multiple partitions to each pod, and host-key affinity is preserved per pod.
- Docker Compose must be updated to create `raw-logs` with 8 partitions.
