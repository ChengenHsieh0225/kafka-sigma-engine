# Log Generator HTTP Admin Endpoint for Runtime EPS Adjustment

The Log Generator exposes a lightweight HTTP admin endpoint (`POST /rate`, `GET /rate`) running in the same asyncio event loop as the producer loop. The EPS rate can be changed at any time during a live demo with a single `curl` call, and the new rate takes effect on the next produce iteration without a container restart.

A Kafka control topic was rejected: the Log Generator is a pure producer; adding a consumer solely for rate control introduces the wrong abstraction and requires producing a Kafka message to adjust a local process setting. Signal-based control (SIGUSR1/SIGUSR2) was rejected because it only supports fixed step increments, not arbitrary target values.

## Consequences

- The Log Generator requires a minimal HTTP server. The Python 3.11 standard library `http.server` running in a background asyncio task is sufficient; no additional dependency is needed.
- Docker Compose and Kubernetes manifests must expose the admin port (default: `8080`) so `curl` can reach it from the host.
- `GET /rate` returns the current EPS for observability without reading logs.
