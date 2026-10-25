"""
In-memory rate limiter for TraceGuard AI authentication and sensitive gateway endpoints.
Thread-safe sliding-window implementation enforcing request frequency thresholds.
"""

from __future__ import annotations
import threading
import time
from typing import Dict, List, Tuple
from fastapi import HTTPException, Request


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter per client IP and action bucket."""

    def __init__(self):
        self._lock = threading.Lock()
        # Key: (bucket_name, client_ip) -> List of timestamp floats
        self._requests: Dict[Tuple[str, str], List[float]] = {}

    def get_client_ip(self, request: Request) -> str:
        """Extracts client IP, respecting X-Forwarded-For if available."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    def check(
        self,
        request: Request,
        bucket: str,
        max_requests: int,
        window_seconds: int = 60,
    ) -> None:
        """
        Enforces rate limiting. Raises HTTP 429 if the request threshold is exceeded.
        """
        client_ip = self.get_client_ip(request)
        key = (bucket, client_ip)
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            timestamps = self._requests.get(key, [])
            # Filter timestamps outside sliding window
            timestamps = [t for t in timestamps if t > window_start]

            if len(timestamps) >= max_requests:
                earliest = timestamps[0]
                retry_after = max(1, int(window_seconds - (now - earliest)))
                self._requests[key] = timestamps
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many requests for {bucket}. Rate limit exceeded. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

            timestamps.append(now)
            self._requests[key] = timestamps

    def reset(self) -> None:
        """Clears all tracked buckets (for test suites)."""
        with self._lock:
            self._requests.clear()


rate_limiter = SlidingWindowRateLimiter()
