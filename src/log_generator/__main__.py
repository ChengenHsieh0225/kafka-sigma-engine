"""Entry point for the Log Generator service.

Reads configuration from environment variables and runs the generator loop.
"""

import asyncio
import os

from aiokafka import AIOKafkaProducer

from src.log_generator.service import LogGeneratorService

_DEFAULT_BOOTSTRAP = "kafka:9092"
_DEFAULT_TOPIC = "raw-logs"
_DEFAULT_EPS = 1000


async def main() -> None:
    """Bootstrap the AIOKafkaProducer and run the log generator indefinitely."""
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", _DEFAULT_BOOTSTRAP)
    topic = os.environ.get("LOG_GENERATOR_TOPIC", _DEFAULT_TOPIC)
    eps = int(os.environ.get("LOG_GENERATOR_EPS", str(_DEFAULT_EPS)))

    producer: AIOKafkaProducer = AIOKafkaProducer(bootstrap_servers=bootstrap)
    await producer.start()
    try:
        service = LogGeneratorService(publisher=producer, topic=topic)
        await service.run(eps=eps)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
