"""Base exception hierarchy for the Kafka Sigma Engine."""


class SigmaEngineError(Exception):
    """Base exception for all Sigma Engine domain errors."""


class LogGeneratorError(SigmaEngineError):
    """Raised when raw log generation fails."""
