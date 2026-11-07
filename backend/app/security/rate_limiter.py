import time
from collections import defaultdict
from fastapi import Request, HTTPException
from backend.app.config import settings

class SlidingWindowRateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self.limit = requests_per_minute
        self.window = 60.0  # seconds
        self.requests = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        now = time.time()
        timestamps = self.requests[client_id]
        
        # Remove timestamps outside current window
        while timestamps and timestamps[0] <= now - self.window:
            timestamps.pop(0)

        if len(timestamps) >= self.limit:
            return False
            
        timestamps.append(now)
        return True

limiter = SlidingWindowRateLimiter(settings.RATE_LIMIT_PER_MINUTE)

async def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Maximum 60 requests per minute allowed."
        )
