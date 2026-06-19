# Elasticsearch for Alert Storage

Alerts are stored in Elasticsearch rather than PostgreSQL. ES is the standard storage layer in real SIEM and XDR platforms, making the portfolio story more credible. Its `_bulk` API maps directly onto the micro-batching flush pattern, and its schema-free dynamic mapping means the Alert document structure can evolve without migrations. The higher operational complexity is acceptable because the service runs locally via Docker Compose.
