# Alert Documents Embed the Full Raw Log

Each Alert stored in Elasticsearch includes the complete Raw Log JSON that triggered the match, rather than a reference or offset pointer back to Kafka. This makes every Alert a self-contained investigation artifact — an analyst querying ES gets the firing rule, severity, timestamp, and the exact log that triggered it in a single document. Kafka's finite retention means raw logs may be unavailable by the time an analyst investigates; embedding eliminates that dependency.

The accepted trade-off is larger ES documents. Given that Alerts are a small fraction of total log volume (only matched logs produce Alerts), the storage overhead is acceptable.

## Alert document fields

| Field | Type | Description |
|---|---|---|
| `alert_id` | UUID | Unique identifier; deduplication key for at-least-once replay |
| `rule_id` | string | Sigma Rule identifier |
| `rule_title` | string | Human-readable rule name |
| `severity` | enum | `low` / `medium` / `high` / `critical`, sourced from the Sigma Rule YAML |
| `matched_at` | UTC timestamp | When the match was detected |
| `host` | string | Source host, denormalized from the Raw Log for fast ES aggregations |
| `raw_log` | object | The full embedded Raw Log JSON |
