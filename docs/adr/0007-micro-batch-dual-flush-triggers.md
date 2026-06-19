# Dual Flush Triggers for Alert Storage Micro-Batching

The Alert Storage Service flushes its in-memory buffer to Elasticsearch when either a size threshold (default: 500 alerts) or a time threshold (default: 5 seconds) is reached, whichever comes first. At high throughput the size threshold dominates, keeping `_bulk` calls efficient. At low throughput the time threshold dominates, bounding alert storage latency. Both values are configurable via environment variables.

Size-only was rejected because it leaves alerts stranded in the buffer during low-traffic periods. Time-only was rejected because it produces undersized bulk calls at high throughput.
