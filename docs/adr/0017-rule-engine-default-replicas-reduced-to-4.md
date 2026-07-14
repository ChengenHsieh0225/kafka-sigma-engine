# Rule Engine Default Replica Count Reduced to 4

The Rule Engine Kubernetes Deployment's default `spec.replicas` is reduced from 8 to 4. This supersedes the "should be configured with `replicas: 8`" consequence in ADR-0012 and ADR-0013 as the *default*, though 8 remains the documented maximum (still matching the 8-partition `raw-logs` topic) and is fully supported via `kubectl scale deployment rule-engine --replicas=8`.

This follows from measuring real `requests`/`limits` usage (via `metrics-server`, not estimates) across every workload on the 4-CPU / 8 GB minikube target:

- With `replicas: 8`, committed `requests` across the stack (2000m CPU from Rule Engine alone, plus Kafka, Elasticsearch, and the observability stack) leave under 200m of the node's ~4000m schedulable capacity unclaimed — before accounting for kube-system's own control-plane pods (apiserver, etcd, coredns, metrics-server) that run on the same single node. Kafka's controller in particular needs real memory headroom (its own JVM heap defaults are uncapped and its usage climbed continuously under sustained load in testing, never clearly plateauing below ~3Gi) that the 8-replica configuration has no room to grant.
- With `replicas: 4`, the same 5-minute sustained-load methodology (EPS 5,000 and 10,000, consumer lag sampled every 30s) showed no throughput regression — lag stayed in the same stable band as the 8-replica configuration, with no growth trend. Each worker's CPU usage rose measurably (to ~85% of its 500m limit at 10,000 EPS, versus a flat, load-insensitive ~250m at 8 replicas) — confirming the per-partition compute cost is real, just diluted below visibility when split across 8 workers instead of 4.
- Total requests at `replicas: 4` leave roughly 1100m of CPU headroom, enough to give Kafka's controller a properly safe memory limit without displacing anything else.

## Consequences

- `k8s/rule-engine/deployment.yaml` ships with `replicas: 4`. `tests/unit/test_k8s_manifests.py` checks for 4, not 8.
- `kubectl scale deployment rule-engine --replicas=8` remains valid and is the documented way to demonstrate the full horizontal-scaling story (ADR-0012) — it is no longer the steady-state default because the resulting CPU budget leaves no room for correctly sizing Kafka.
- If Kafka's own resource footprint is later reduced (e.g. an explicit `KAFKA_HEAP_OPTS`) or the minikube profile is given more than 4 CPUs, revisiting the default back toward 8 is reasonable — this ADR records a resource-budget trade-off on today's target hardware, not a claim that 8 replicas are architecturally wrong.
