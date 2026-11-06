"""Tiny in-memory failure limiter for login attempts.

Per-process only (documented in THREATS.md): deploy with a single worker,
or move this to Redis/the database if you scale out.
"""
import threading
import time
from collections import defaultdict, deque


class FailureLimiter:
    def __init__(self, window_seconds=900):
        self.window = window_seconds
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key, now):
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, key, limit):
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= limit

    def record(self, key):
        with self._lock:
            now = time.monotonic()
            self._prune(key, now).append(now)

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)

    def clear(self):
        with self._lock:
            self._hits.clear()


limiter = FailureLimiter()
