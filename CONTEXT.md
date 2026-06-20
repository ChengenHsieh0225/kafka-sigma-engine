# Kafka Sigma Engine

A high-throughput, low-latency log ingestion and threat detection pipeline that simulates a cloud-native XDR platform. Sigma Rules are evaluated against a continuous stream of Raw Logs; matches produce Alerts that are stored for investigation.

## Language

### Detection

**Raw Log**:
A single JSON-formatted security log entry representing one discrete system activity, sourced from environments such as Windows Event Logs or AWS CloudTrail. Always carries `timestamp`, `host`, and `log_type`; all other fields (e.g. `event_id`, `username`, `process_name`, `source_ip`, `action`) are optional and vary by log type.
_Avoid_: Event (too generic in distributed-systems contexts), log entry, record

**Sigma Rule**:
An open-source YAML document that declares the field conditions a Raw Log must satisfy for a threat to be detected. Scoped to Level 2 conditions: field equality, string modifiers (`contains`, `startswith`, `endswith`), and boolean logic (`and`/`or`/`not`).
_Avoid_: Detection rule, policy, filter

**Alert**:
The data structure produced when a Raw Log satisfies all conditions of a Sigma Rule. Carries the matched rule's identity, the original Raw Log, and a timestamp.
_Avoid_: Rule Match, Finding, Detection hit

**Rule Lifecycle**:
The progression of a Sigma Rule from creation by an Information Security Engineer through delivery to the running Rule Engine. Rules can be added, updated, or deleted in a live system without restart, via typed JSON operation envelopes published to the `rule-updates` Kafka topic.
_Avoid_: Rule management, rule update

**Attack Sequence**:
A series of Raw Logs from the same host that collectively represent a realistic threat actor behaviour pattern — for example, repeated failed logins followed by a successful login and privilege escalation. Produced by the Log Generator's per-host state machine; detected by time-window aggregation Sigma Rules.
_Avoid_: Attack chain, event correlation, log sequence

### Pipeline

**Ingestion Pipeline**:
The end-to-end asynchronous data stream, managed by Kafka, that decouples Raw Log generation, rule evaluation, and Alert storage into independent microservices.
_Avoid_: Data pipeline, event stream

**Micro-Batching**:
The technique used by the Alert Storage Service to accumulate Alerts in an in-memory buffer and flush them to the storage backend in groups, reducing per-write I/O overhead.
_Avoid_: Buffering, bulk insert, batch write
