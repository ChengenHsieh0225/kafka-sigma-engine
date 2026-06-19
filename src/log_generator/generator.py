"""Raw log generation for the Kafka Sigma Engine."""

import datetime
import random
from typing import Any

from src.exceptions import LogGeneratorError


HOSTS: list[str] = ["web-01", "web-02", "db-01", "db-02", "auth-01"]
LOG_TYPES: list[str] = ["windows_event", "cloudtrail"]

_WINDOWS_EVENT_IDS: list[int] = [4624, 4625, 4648, 4672, 4688]
_CLOUDTRAIL_ACTIONS: list[str] = [
    "GetObject",
    "DeleteBucket",
    "ListBuckets",
    "PutObject",
    "CreateUser",
]
_USERNAMES: list[str] = ["alice", "bob", "carol", "dave", "svc-backup"]
_PROCESS_NAMES: list[str] = ["lsass.exe", "cmd.exe", "powershell.exe", "svchost.exe"]


def generate_raw_log(
    hosts: list[str] | None = None,
    log_types: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a single Raw Log with required and type-appropriate optional fields.

    Args:
        hosts: Pool of host names to sample from. Defaults to HOSTS.
        log_types: Pool of log types to sample from. Defaults to LOG_TYPES.

    Returns:
        A dict with at least ``timestamp``, ``host``, and ``log_type`` keys.
        Windows event logs also include ``event_id``, ``username``, and
        ``process_name``. CloudTrail logs include ``action`` and ``source_ip``.

    Raises:
        LogGeneratorError: If either pool is empty.
    """
    if hosts is None:
        hosts = HOSTS
    if log_types is None:
        log_types = LOG_TYPES

    if not hosts:
        raise LogGeneratorError("hosts pool must not be empty")
    if not log_types:
        raise LogGeneratorError("log_types pool must not be empty")

    host = random.choice(hosts)
    log_type = random.choice(log_types)

    log: dict[str, Any] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": host,
        "log_type": log_type,
    }

    if log_type == "windows_event":
        log["event_id"] = random.choice(_WINDOWS_EVENT_IDS)
        log["username"] = random.choice(_USERNAMES)
        log["process_name"] = random.choice(_PROCESS_NAMES)
    elif log_type == "cloudtrail":
        log["action"] = random.choice(_CLOUDTRAIL_ACTIONS)
        log["source_ip"] = (
            f"10.{random.randint(0, 255)}"
            f".{random.randint(0, 255)}"
            f".{random.randint(0, 255)}"
        )

    return log
