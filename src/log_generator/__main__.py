"""Entry point for the Log Generator service.

Reads configuration from environment variables and runs the generator loop
alongside an HTTP admin server for runtime EPS control (ADR-0015).
"""

import asyncio
import os
from http.server import HTTPServer

from aiokafka import AIOKafkaProducer

from src.log_generator.admin import LogAdminHandler
from src.log_generator.service import LogGeneratorService

_DEFAULT_BOOTSTRAP = "kafka:9092"
_DEFAULT_TOPIC = "raw-logs"
_DEFAULT_EPS = 1000
_DEFAULT_ADMIN_PORT = 8080


async def _run_admin_server(service: LogGeneratorService, port: int) -> None:
    """Run the HTTP admin server in a thread-pool executor (non-blocking)."""
    Handler = type("_AdminHandler", (LogAdminHandler,), {"service": service})
    server = HTTPServer(("", port), Handler)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, server.serve_forever)


async def main() -> None:
    """Bootstrap the AIOKafkaProducer and run the log generator indefinitely."""
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", _DEFAULT_BOOTSTRAP)
    topic = os.environ.get("LOG_GENERATOR_TOPIC", _DEFAULT_TOPIC)
    eps = int(os.environ.get("LOG_GENERATOR_EPS", str(_DEFAULT_EPS)))
    admin_port = int(os.environ.get("LOG_GENERATOR_ADMIN_PORT", str(_DEFAULT_ADMIN_PORT)))

    producer: AIOKafkaProducer = AIOKafkaProducer(bootstrap_servers=bootstrap)
    await producer.start()
    try:
        service = LogGeneratorService(
            publisher=producer,
            topic=topic,
            use_state_machine=True,
        )
        asyncio.create_task(_run_admin_server(service, admin_port))
        await service.run(eps=eps)
    finally:
        await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())
