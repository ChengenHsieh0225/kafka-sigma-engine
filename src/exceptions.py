"""Base exception hierarchy for the Kafka Sigma Engine."""


class SigmaEngineError(Exception):
    """Base exception for all Sigma Engine domain errors."""


class LogGeneratorError(SigmaEngineError):
    """Raised when raw log generation fails."""


class RuleEngineError(SigmaEngineError):
    """Raised when rule loading or evaluation fails."""


class AlertStorageError(SigmaEngineError):
    """Raised when alert storage or Elasticsearch operations fail."""
