import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status


class FixedWindowRateLimiter:
    def __init__(self) -> None:
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        bucket = self._requests[key]
        window_start = now - window_seconds

        while bucket and bucket[0] <= window_start:
            bucket.popleft()

        if len(bucket) >= limit:
            return False

        bucket.append(now)
        return True


limiter = FixedWindowRateLimiter()


def enforce_rate_limit(
    request: Request,
    scope: str,
    limit: int,
    window_seconds: int = 60,
    identifier: str | None = None,
) -> None:
    client_host = request.client.host if request.client else "unknown"
    key = f"{scope}:{client_host}:{identifier or '*'}"

    if not limiter.allow(key, limit, window_seconds):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
        )
