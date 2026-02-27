import os
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Mount
from app.db.database import engine, Base
from app.api.auth import router as auth_router
from app.api.scan import router as scan_router
from app.api.usage import router as usage_router
from app.api.webhooks import router as webhooks_router
from app.api.admin import router as admin_router
from app.api.billing import router as billing_router
from app.feeds.scheduler import lifespan
from app.middleware.rate_limit import RateLimitMiddleware
from app.config import get_settings

logger = logging.getLogger(__name__)

# Create tables
Base.metadata.create_all(bind=engine)

settings = get_settings()

# Production mode: disable docs completely
IS_PRODUCTION = os.getenv("ENVIRONMENT", "production") == "production"

app = FastAPI(
    title="API",  # Generic name - don't reveal service identity
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if IS_PRODUCTION else "/docs",  # Disable in production
    redoc_url=None if IS_PRODUCTION else "/redoc",  # Disable in production
    openapi_url=None if IS_PRODUCTION else "/openapi.json",  # Disable schema
)


# Security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        # Remove server header
        if "server" in response.headers:
            del response.headers["server"]
        return response


# Add middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)


@app.get("/health")
def health_check():
    return {"status": "ok"}  # Minimal response


@app.get("/")
def root():
    return {"status": "ok"}  # Don't reveal service name or version


@app.get("/quickstart")
def quickstart():
    return {
        "service": "SecurityScan API",
        "description": "AI skill security analysis — detects vulnerabilities, malicious patterns and supply chain risks in GitHub-hosted skills.",
        "base_url": "https://apisecurityscan.net",
        "authentication": {
            "header": "X-API-Key: <api_key>",
            "key_format": "ss_live_...",
            "note": "Register first to obtain a free API key. Key is returned immediately at registration.",
        },
        "steps": [
            {
                "step": 1,
                "action": "Register and get a free API key",
                "method": "POST",
                "endpoint": "/auth/register",
                "body": {
                    "agent_id": "your-agent-id@yourdomain.com",
                    "plan": "FREE",
                },
                "note": "FREE plan includes 5 scans/month. Use agent_id for AI agents or email for human users.",
                "response": {
                    "api_key": "ss_live_... — save this key",
                    "plan": "FREE",
                    "scans_remaining": 5,
                },
            },
            {
                "step": 2,
                "action": "Upgrade plan (optional)",
                "method": "POST",
                "endpoint": "/billing/upgrade",
                "headers": {"X-API-Key": "ss_live_..."},
                "body": {"plan": "PAY_PER_SCAN"},
                "plans": {
                    "FREE": "5 scans/month — no payment required",
                    "PAY_PER_SCAN": "MXN $2/scan — pay only for what you use",
                    "PRO": "MXN $399/month — unlimited scans",
                },
                "response": {
                    "checkout_url": "Open this URL to complete payment",
                },
            },
            {
                "step": 3,
                "action": "Scan a skill",
                "method": "POST",
                "endpoint": "/scan",
                "headers": {"X-API-Key": "ss_live_..."},
                "body": {"skill_url": "https://github.com/owner/repo"},
                "important": [
                    "skill_url must be a github.com URL — not raw.githubusercontent.com",
                    "The scanner fetches and analyzes the repository code",
                ],
                "response_fields": {
                    "score": "0-100 safety score",
                    "recommendation": "SAFE | CAUTION | DANGEROUS",
                    "issues": "List of detected issues with severity and line numbers",
                    "cached": "true if result is from cache (faster, no credit consumed)",
                },
            },
        ],
        "common_errors": {
            "401 API key required": "Missing X-API-Key header",
            "401 Invalid API key": "Key not found — register first at /auth/register",
            "403 Scan limit reached": "Upgrade plan at /billing/upgrade",
            "fetch_error in issues": "Repository not accessible — check the URL is public and uses github.com format",
        },
    }


# Include routers (admin routes hidden from schema in production)
app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(usage_router)
app.include_router(webhooks_router)
app.include_router(billing_router)
app.include_router(admin_router, include_in_schema=not IS_PRODUCTION)


# Mount MCP server for AI agent integration
try:
    from app.mcp_server import get_mcp_app
    mcp_app = get_mcp_app()
    app.router.routes.append(Mount("/mcp", app=mcp_app))
    logger.info("MCP server mounted at /mcp")
except ImportError as e:
    logger.warning(f"MCP server not available: {e}")
