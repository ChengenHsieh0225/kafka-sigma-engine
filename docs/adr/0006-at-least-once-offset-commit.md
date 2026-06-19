# Manual At-Least-Once Offset Commits in the Rule Engine

The Rule Engine commits Kafka offsets manually, only after the Raw Log has been evaluated and any resulting Alert has been successfully published to the `alerts` topic. This guarantees no logs are dropped on restart — uncommitted offsets are replayed from the last committed position. The accepted trade-off is that logs processed but not yet committed may be reprocessed after a crash, potentially producing duplicate Alerts. Duplicates are tolerable in a detection system and can be deduplicated at query time by Alert ID.

Auto-commit was rejected because it commits on a timer independent of processing completion, creating a window where a crash silently drops logs. Exactly-once semantics (Kafka transactions) were rejected as disproportionate complexity for this project's scope.
