"""In-memory sliding window for per-host time-window aggregation rules.

Each SlidingWindow tracks a deque of timestamps per host. Timestamps older
than the requested window are evicted on each count() call, keeping memory
bounded to the number of events within the active window per host.

Thread-safety is not required: each Rule Engine worker is a single asyncio
process and raw-logs are partitioned by host (ADR-0005/ADR-0012), so all
events for a given host flow to exactly one worker.
"""

import time
from collections import defaultdict, deque
from typing import Callable


class SlidingWindow:
    """Counts per-host events within a sliding time window.

    Args:
        now: Clock function returning the current time as a float (seconds).
             Defaults to ``time.monotonic``. Inject a controlled clock in tests.
    """

    def __init__(self, now: Callable[[], float] | None = None) -> None:
        self._now: Callable[[], float] = now if now is not None else time.monotonic
        self._buckets: defaultdict[str, deque[float]] = defaultdict(deque)

    def add(self, host: str, ts: float | None = None) -> None:
        """Record one event for *host* at time *ts* (defaults to now).

        Args:
            host: Source host identifier.
            ts: Explicit event timestamp in seconds. Defaults to ``now()``.
        """
        self._buckets[host].append(ts if ts is not None else self._now())

    def count(self, host: str, window_seconds: float) -> int:
        """Return the number of events for *host* within the last *window_seconds*.

        Events older than ``now() - window_seconds`` are evicted before counting.

        Args:
            host: Source host identifier.
            window_seconds: Width of the sliding window in seconds.

        Returns:
            Number of events within the window.
        """
        now = self._now()
        cutoff = now - window_seconds
        dq = self._buckets[host]
        while dq and dq[0] <= cutoff:
            dq.popleft()
        return len(dq)
