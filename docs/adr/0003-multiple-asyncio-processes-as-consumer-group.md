# Multiple Independent Asyncio Processes as the Rule Engine Worker Pool

The Rule Engine's "worker pool" is implemented as N independent Python processes, each running its own asyncio event loop and participating in the same Kafka consumer group on `raw-logs`. Kafka distributes partitions across processes, achieving parallelism without shared memory or IPC. This sidesteps the GIL for CPU-bound matching and keeps each process simple. Scaling is done by increasing N (or adding containers).

`ProcessPoolExecutor` within a single process was rejected because it requires serializing Sigma Rules and Raw Logs across process boundaries on every task, adding overhead and complexity that outweighs the benefit.

## Consequences

Each Rule Engine process must also independently consume from the `rule-updates` topic using its own unique consumer group ID, so that every process receives every new Sigma Rule (fan-out), rather than only one process receiving each rule (competing consumers).
