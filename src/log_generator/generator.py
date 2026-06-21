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

# Suspicious processes emitted by the lateral_moving state
_SUSPICIOUS_PROCESSES: list[str] = ["cmd.exe", "powershell.exe", "lsass.exe"]

# Valid state names (ADR-0016)
State = str  # 'idle' | 'brute_forcing' | 'compromised' | 'lateral_moving'

# Transition table: state → [(next_state, weight), ...]
_TRANSITIONS: dict[str, list[tuple[str, float]]] = {
    "idle": [("brute_forcing", 0.05), ("idle", 0.95)],
    "brute_forcing": [("compromised", 0.10), ("idle", 0.05), ("brute_forcing", 0.85)],
    "compromised": [("lateral_moving", 0.50), ("idle", 0.50)],
    "lateral_moving": [("idle", 0.30), ("lateral_moving", 0.70)],
}


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


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
        "timestamp": _now_iso(),
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


class HostStateMachine:
    """Per-host state machine that emits correlated attack-sequence Raw Logs (ADR-0016).

    Each host transitions between states (idle, brute_forcing, compromised,
    lateral_moving) with configurable probabilities. The emitted log type is
    determined by the current state, producing burst patterns that trigger
    time-window aggregation rules.

    Args:
        hosts: Initial pool of host names. Additional hosts are auto-registered
               in the ``idle`` state on first use.
    """

    def __init__(self, hosts: list[str] | None = None) -> None:
        self._states: dict[str, State] = {h: "idle" for h in (hosts or [])}

    def state(self, host: str) -> State:
        """Return the current state for *host* (auto-registers as 'idle')."""
        return self._states.setdefault(host, "idle")

    def _force_state(self, host: str, state: State) -> None:
        """Override the state for *host*. Intended for testing only."""
        self._states[host] = state

    def _transition(self, host: str) -> None:
        current = self._states.setdefault(host, "idle")
        options = _TRANSITIONS[current]
        next_state = random.choices(
            [s for s, _ in options],
            weights=[w for _, w in options],
            k=1,
        )[0]
        self._states[host] = next_state

    def emit(self, host: str) -> dict[str, Any]:
        """Emit one Raw Log for *host* based on its current state, then transition.

        Args:
            host: Source host identifier.

        Returns:
            A Raw Log dict matching the schema expected by the Rule Engine.
        """
        current = self._states.setdefault(host, "idle")

        if current == "brute_forcing":
            log: dict[str, Any] = {
                "timestamp": _now_iso(),
                "host": host,
                "log_type": "windows_event",
                "event_id": 4625,
                "username": random.choice(_USERNAMES),
            }
        elif current == "compromised":
            event_id = random.choice([4624, 4672])
            log = {
                "timestamp": _now_iso(),
                "host": host,
                "log_type": "windows_event",
                "event_id": event_id,
                "username": random.choice(_USERNAMES),
            }
        elif current == "lateral_moving":
            log = {
                "timestamp": _now_iso(),
                "host": host,
                "log_type": "windows_event",
                "event_id": 4688,
                "username": random.choice(_USERNAMES),
                "process_name": random.choice(_SUSPICIOUS_PROCESSES),
            }
        else:
            # idle → random baseline noise
            log = generate_raw_log(hosts=[host])

        self._transition(host)
        return log
