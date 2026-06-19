"""Async log generator service for the Kafka Sigma Engine."""

import asyncio
import json
from typing import Any, Protocol

from src.log_generator.generator import HOSTS, LOG_TYPES, generate_raw_log


class KafkaPublisher(Protocol):
    """Structural interface for publishing bytes to a Kafka topic."""

    async def send(
        self,
        topic: str,
        value: bytes | None = None,
        key: bytes | None = None,
    ) -> Any:
        """Publish a message to *topic* with an optional key."""
        ...


class LogGeneratorService:
    """Generates and publishes Raw Logs to a Kafka topic.

    Args:
        publisher: Kafka publisher conforming to KafkaPublisher.
        topic: Destination Kafka topic name.
        hosts: Pool of host names for log generation. Defaults to HOSTS.
        log_types: Pool of log types for log generation. Defaults to LOG_TYPES.
    """

    def __init__(
        self,
        publisher: KafkaPublisher,
        topic: str,
        hosts: list[str] | None = None,
        log_types: list[str] | None = None,
    ) -> None:
        self._publisher = publisher
        self._topic = topic
        self._hosts = hosts if hosts is not None else HOSTS
        self._log_types = log_types if log_types is not None else LOG_TYPES

    async def send_one(self) -> None:
        """Generate and publish a single Raw Log.

        The Kafka message key is set to the log's ``host`` field so that all
        logs from the same source machine are routed to the same partition.
        """
        log = generate_raw_log(self._hosts, self._log_types)
        key = log["host"].encode()
        value = json.dumps(log).encode()
        await self._publisher.send(self._topic, value=value, key=key)

    async def run(self, eps: int) -> None:
        """Continuously publish Raw Logs at the target rate.

        Args:
            eps: Target events per second. Controls the inter-message sleep
                 interval (``1 / eps`` seconds).
        """
        interval = 1.0 / eps
        while True:
            await self.send_one()
            await asyncio.sleep(interval)
