from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger(__name__)


class RateLimiter:
    """Adaptive rate limiter with configurable base delay.

    On 429/503 responses the delay is multiplied (adaptive backoff).
    On success the delay decays back toward the base.
    """

    def __init__(self, base_delay_sec: float = 0.0):
        self._base_delay = base_delay_sec
        self._current_delay = base_delay_sec
        self._max_delay = 30.0
        self._multiplier = 2.0
        self._recovery = 0.9
        self._last_request = 0.0
        self._lock = threading.Lock()

    def acquire(self):
        """Sleep if needed to respect the current delay."""
        if self._current_delay <= 0:
            return
        with self._lock:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self._current_delay:
                sleep_for = self._current_delay - elapsed
                time.sleep(sleep_for)
            self._last_request = time.monotonic()

    def on_throttle(self):
        """Increase delay on throttle signals (429, 503)."""
        with self._lock:
            self._current_delay = min(
                self._current_delay * self._multiplier, self._max_delay
            )
            log.debug("Rate limiter backed off to %.2fs", self._current_delay)

    def on_success(self):
        """Gradually reduce delay toward base on success."""
        with self._lock:
            self._current_delay = max(
                self._base_delay, self._current_delay * self._recovery
            )

    @property
    def current_delay(self) -> float:
        return self._current_delay
