"""Per-IP and global token buckets.  Pure Python, O(1) memory per client."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from . import util


@dataclass
class Bucket:
    tokens: float
    last: float
    strikes: int = 0


class RateLimiter:
    def __init__(self, per_ip_burst: int = 30, per_ip_rate: float = 1.5,
                 global_burst: int = 500, global_rate: float = 40.0,
                 max_clients: int = 50000):
        self.per_ip_burst = max(2, int(per_ip_burst))
        self.per_ip_rate = max(0.05, float(per_ip_rate))
        self.global_burst = max(10, int(global_burst))
        self.global_rate = max(1.0, float(global_rate))
        self.max_clients = max(100, int(max_clients))
        self._lock = threading.RLock()
        self._ips = {}
        self._global = Bucket(tokens=float(self.global_burst), last=time.time())

    def _refill(self, b: Bucket, rate: float, burst: int, now: float):
        elapsed = max(0.0, now - b.last)
        b.tokens = min(float(burst), b.tokens + elapsed * rate)
        b.last = now

    def allow(self, ip: str, cost: float = 1.0, strict: bool = False):
        now = time.time()
        with self._lock:
            self._refill(self._global, self.global_rate, self.global_burst, now)
            if self._global.tokens < cost:
                return {"ok": False, "reason": "global", "retry_after": 1}
            bucket = self._ips.get(ip)
            if bucket is None:
                if len(self._ips) >= self.max_clients:
                    old = sorted(self._ips.items(), key=lambda kv: kv[1].last)[:max(1, len(self._ips) // 10)]
                    for k, _ in old:
                        self._ips.pop(k, None)
                bucket = Bucket(tokens=float(self.per_ip_burst), last=now)
                self._ips[ip] = bucket
            rate = self.per_ip_rate * (0.35 if strict else 1.0)
            burst = max(2, int(self.per_ip_burst * (0.4 if strict else 1.0)))
            self._refill(bucket, rate, burst, now)
            if bucket.tokens < cost:
                bucket.strikes += 1
                wait = (cost - bucket.tokens) / max(rate, 0.01)
                return {"ok": False, "reason": "per_ip", "retry_after": max(1, int(wait + 0.999)),
                        "strikes": bucket.strikes}
            bucket.tokens -= cost
            self._global.tokens -= cost
            return {"ok": True, "tokens": round(bucket.tokens, 2), "strikes": bucket.strikes}

    def strikes(self, ip: str) -> int:
        with self._lock:
            b = self._ips.get(ip)
            return b.strikes if b else 0

    def snapshot(self, limit: int = 10) -> list:
        with self._lock:
            rows = sorted(self._ips.items(), key=lambda kv: -kv[1].strikes)[:limit]
            return [{"ip": ip, "strikes": b.strikes, "tokens": round(b.tokens, 2)} for ip, b in rows]
