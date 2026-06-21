"""Async log generator service for the Kafka Sigma Engine."""

import asyncio
import json
import random
from typing import Any, Protocol

from src.log_generator.generator import HOSTS, LOG_TYPES, HostStateMachine, generate_raw_log


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

    When ``use_state_machine=True`` the service uses a per-host state machine
    (ADR-0016) to emit correlated attack sequences that trigger time-window
    aggregation rules. Otherwise it falls back to purely random log generation.

    Args:
        publisher: Kafka publisher conforming to KafkaPublisher.
        topic: Destination Kafka topic name.
        hosts: Pool of host names for log generation. Defaults to HOSTS.
        log_types: Pool of log types for log generation (random mode only).
                   Defaults to LOG_TYPES.
        use_state_machine: If True, use the per-host state machine for log
                           generation. Defaults to False for backward compatibility.
    """

    def __init__(
        self,
        publisher: KafkaPublisher,
        topic: str,
        hosts: list[str] | None = None,
        log_types: list[str] | None = None,
        *,
        use_state_machine: bool = False,
    ) -> None:
        self._publisher = publisher
        self._topic = topic
        self._hosts = hosts if hosts is not None else HOSTS
        self._log_types = log_types if log_types is not None else LOG_TYPES
        self._state_machine = HostStateMachine(self._hosts) if use_state_machine else None

    def _next_log(self) -> dict[str, Any]:
        if self._state_machine is not None:
            host = random.choice(self._hosts)
            return self._state_machine.emit(host)
        return generate_raw_log(self._hosts, self._log_types)

    async def send_one(self) -> None:
        """Generate and publish a single Raw Log.

        The Kafka message key is set to the log's ``host`` field so that all
        logs from the same source machine are routed to the same partition.
        """
        log = self._next_log()
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
