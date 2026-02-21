"""Simple in-memory rate limiting middleware."""

import time
import logging
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiter based on API key or IP address.

    Limits:
    - FREE tier: 10 requests/minute
    - PAY_PER_SCAN tier: 60 requests/minute
    - PRO tier: 300 requests/minute
    - No API key (public endpoints): 30 requests/minute per IP
    """

    LIMITS = {
        "FREE": 10,
        "PAY_PER_SCAN": 60,
        "PRO": 300,
        "PUBLIC": 30,
    }

    def __init__(self, app):
        super().__init__(app)
        self.requests = defaultdict(list)  # key -> list of timestamps

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health/docs endpoints
        if request.url.path in ["/health", "/docs", "/openapi.json", "/"]:
            return await call_next(request)

        # Get rate limit key and tier
        api_key = request.headers.get("X-API-Key")

        # Admin requests bypass rate limiting (admin uses Authorization: Bearer)
        auth_header = request.headers.get("Authorization", "")
        if request.url.path.startswith("/_s/") and auth_header.startswith("Bearer "):
            return await call_next(request)

        # Get client IP (handle None for test environments)
        client_ip = request.client.host if request.client else "test"

        if api_key:
            # Get user tier from database (simplified - in production use cache)
            from app.db.database import SessionLocal
            from app.db.crud import get_user_by_api_key

            db = SessionLocal()
            try:
                user = get_user_by_api_key(db, api_key)
                if user:
                    tier = user.plan
                    key = f"user:{user.id}"
                else:
                    tier = "PUBLIC"
                    key = f"ip:{client_ip}"
            finally:
                db.close()
        else:
            tier = "PUBLIC"
            key = f"ip:{client_ip}"

        # Check rate limit
        limit = self.LIMITS.get(tier, self.LIMITS["PUBLIC"])
        now = time.time()
        window_start = now - 60  # 1 minute window

        # Clean old requests
        self.requests[key] = [t for t in self.requests[key] if t > window_start]

        if len(self.requests[key]) >= limit:
            logger.warning(f"Rate limit exceeded for {key} (tier: {tier})")
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "rate_limit_exceeded",
                    "message": f"Rate limit exceeded. Limit: {limit} requests/minute for {tier} tier.",
                    "retry_after": 60
                }
            )

        # Record this request
        self.requests[key].append(now)

        return await call_next(request)
