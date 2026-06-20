# Typed JSON Envelope for Rule Lifecycle Operations on `rule-updates`

The `rule-updates` Kafka topic is extended from bare Sigma Rule YAML to a typed JSON envelope that supports add, update, and delete operations:

```json
{"op": "add" | "update" | "delete", "rule_id": "...", "rule": { /* Sigma Rule fields */ }}
```

The `rule` field is omitted for `delete` operations. This supersedes the add-only bare-YAML format from ADR-0001.

Kafka tombstones (null-value messages keyed by `rule_id`) were rejected because they require enabling log compaction on the topic, are less self-describing in logs and monitoring, and silently fail when a producer sends a null value by accident.

## Consistency model

Each Rule Engine worker evaluates each Raw Log against an immutable snapshot of the current rule set (a Python reference copy taken at the start of each evaluation). An update or delete received mid-evaluation takes effect on the next Raw Log, not the current one. This is safe, O(1), and lock-free.

## Consequences

- The `Rule Lifecycle` domain term in `CONTEXT.md` must be updated: rules can now be added, updated, and deleted at runtime without restart.
- Producers sending to `rule-updates` must now send JSON, not bare YAML. The existing Kafka console producer hot-reload example in the README must be updated to wrap the rule in the envelope format.
- Workers must handle malformed or unrecognised `op` values gracefully (log and skip).
