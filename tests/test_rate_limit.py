import time

from spartan.rate_limit import RateLimiter


class TestRateLimiter:
    def test_no_delay_first_call(self):
        rl = RateLimiter(base_delay_sec=0.0)
        t0 = time.monotonic()
        rl.acquire()
        dt = time.monotonic() - t0
        assert dt < 0.05

    def test_delay_on_second_call(self):
        rl = RateLimiter(base_delay_sec=0.2)
        rl.acquire()
        t0 = time.monotonic()
        rl.acquire()
        dt = time.monotonic() - t0
        assert dt >= 0.18

    def test_backoff_on_throttle(self):
        rl = RateLimiter(base_delay_sec=0.1)
        rl.acquire()
        rl.on_throttle()
        t0 = time.monotonic()
        rl.acquire()
        dt = time.monotonic() - t0
        assert dt >= 0.18

    def test_recovery(self):
        rl = RateLimiter(base_delay_sec=0.1)
        rl.acquire()
        rl.on_throttle()
        rl.on_success()
        t0 = time.monotonic()
        rl.acquire()
        dt = time.monotonic() - t0
        assert dt >= 0.08
