# Alert Deduplication via Elasticsearch Document ID

Duplicate Alerts produced by Kafka at-least-once replay are deduplicated by setting the Elasticsearch document `_id` to `alert_id` in the `_bulk` action metadata. ES guarantees that indexing the same `_id` twice is an idempotent upsert — the second write overwrites the first without creating a duplicate document.

This supersedes the PRD decision to defer deduplication to query time.

The required change is minimal: `_ESIndexer.bulk_index()` in the Alert Storage Service adds `"_id": doc["alert_id"]` to each `_bulk` action entry.

Alternative approaches were rejected:
- **Query-time collapse** — every query must remember to collapse on `alert_id`; dashboards silently double-count if forgotten.
- **In-memory `seen_ids` set** — unbounded growth, lost on restart, duplicates re-admitted after recovery.
- **Separate deduplication service** — a full microservice whose only job is a set-membership check; disproportionate complexity.
