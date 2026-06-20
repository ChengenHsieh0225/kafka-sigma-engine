# Log Generator Per-Host State Machine for Correlated Attack Sequences

The Log Generator simulates correlated attack behaviour by running a state machine per host. Each host transitions through named states (`idle`, `brute_forcing`, `compromised`, `lateral_moving`) with configurable transition probabilities. The emitted Raw Log type is determined by the current state:

| State | Emitted events |
|---|---|
| `idle` | Random mix — baseline noise |
| `brute_forcing` | Rapid `event_id 4625` (failed login) bursts from the same host |
| `compromised` | `event_id 4624` (successful login) followed by `event_id 4672` (privilege use) |
| `lateral_moving` | `event_id 4688` (process creation) with suspicious `process_name` values |

This directly produces the per-host burst patterns that trigger time-window aggregation rules (ADR-0010), without pre-scripting finite sequences.

A YAML scenario playbook was rejected: it is deterministic but rigid — adding a new attack pattern requires a new config file. Weighted random was rejected: it cannot guarantee a complete attack chain fires within a time window, making aggregation rule demonstration unreliable.

## Consequences

- The generator state is `dict[host, State]`, updated on each emit cycle. State is held in-process and lost on restart (acceptable — the generator is a simulation tool, not a fault-tolerant service).
- New attack states can be added by extending the state transition table, with no structural changes to the generator.
- The six new Sigma Rules (Enhancement 1) should be designed to fire against the events emitted by these states, so the Grafana Alert panel shows realistic detection activity.
