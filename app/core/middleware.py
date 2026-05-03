from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
import time
from collections import defaultdict

# Simple in-memory rate limiter for MVP (30 requests / minute)
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.rate_limit_records = defaultdict(list)
        self.limit = 30
        self.window = 60 # 60 seconds

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        
        # Clean up old records
        self.rate_limit_records[client_ip] = [
            req_time for req_time in self.rate_limit_records[client_ip] 
            if now - req_time < self.window
        ]
        
        # Only rate limit the scanner API for now to avoid blocking static files
        if request.url.path.startswith("/api/scan"):
            if len(self.rate_limit_records[client_ip]) >= self.limit:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too Many Requests. Limit is 30 scans per minute."}
                )
            self.rate_limit_records[client_ip].append(now)
            
        response = await call_next(request)
        return response
