# `raw-logs` Topic: 4 Partitions, Keyed by Source Host

The `raw-logs` Kafka topic uses 4 partitions, giving the Rule Engine consumer group a concrete, demonstrable pool of 4 parallel worker processes. Logs are partitioned by source host identifier so all events from the same machine are routed to the same partition and processed by the same Rule Engine process in order. This preserves per-host event ordering and leaves the door open for future stateful detections (e.g., brute-force threshold rules) without requiring a topology change.

Round-robin (no key) was rejected because it would make per-host stateful detection impossible to add later without repartitioning.
