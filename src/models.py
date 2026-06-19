"""Shared domain models for the Kafka Sigma Engine."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SigmaRule:
    """A parsed Sigma Rule ready for in-memory evaluation.

    Args:
        id: Unique rule identifier from the YAML ``id`` field.
        title: Human-readable rule name from the YAML ``title`` field.
        level: Severity level (``low``, ``medium``, ``high``, ``critical``).
        detection: Raw detection dict parsed from the YAML ``detection`` block.
    """

    id: str
    title: str
    level: str
    detection: dict[str, Any]


@dataclass
class Alert:
    """Produced when a Raw Log satisfies all conditions of a Sigma Rule.

    Args:
        alert_id: UUID identifying this alert (for at-least-once deduplication).
        rule_id: ID of the Sigma Rule that triggered this alert.
        rule_title: Title of the triggering rule.
        severity: Severity copied from the triggering rule's ``level``.
        matched_at: ISO 8601 UTC timestamp of the match.
        host: Host field copied from the triggering Raw Log (denormalised).
        raw_log: Full Raw Log JSON that triggered the alert.
    """

    alert_id: str
    rule_id: str
    rule_title: str
    severity: str
    matched_at: str
    host: str
    raw_log: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the Alert to a plain dict suitable for Elasticsearch indexing."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "host": self.host,
            "raw_log": self.raw_log,
        }
