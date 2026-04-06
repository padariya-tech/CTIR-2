"""
CTIR — Security utilities
• Optional API-key authentication for protected endpoints
• Request ID injection middleware
• Rate limiting helpers
"""

import secrets
import time
import uuid
from typing import Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

# ── API Key auth ──────────────────────────────────────────────────────────────

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    api_key: Optional[str] = Security(_api_key_header),
) -> str:
    """
    FastAPI dependency — enforces X-API-Key header.
    If API_SECRET_KEY is empty / 'dev-secret-key', auth is skipped (dev mode).
    """
    secret = settings.API_SECRET_KEY
    if secret in ("", "dev-secret-key"):
        return "dev-mode"

    if not api_key or not secrets.compare_digest(api_key, secret):
        logger.warning("unauthorized_request", provided_key=str(api_key)[:8])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
    return api_key


# ── Request ID middleware ─────────────────────────────────────────────────────

class RequestIDMiddleware:
    """
    Injects a unique X-Request-ID into every request/response.
    Logs the method, path, status, and latency for each request.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        scope["request_id"] = request_id
        t0 = time.monotonic()

        async def send_with_id(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append(
                    (b"x-request-id", request_id.encode())
                )
                message = {**message, "headers": headers}
                status_code = message.get("status", 0)
                latency_ms = int((time.monotonic() - t0) * 1000)
                logger.info(
                    "http_request",
                    request_id=request_id,
                    method=scope.get("method", ""),
                    path=scope.get("path", ""),
                    status_code=status_code,
                    latency_ms=latency_ms,
                )
            await send(message)

        await self.app(scope, receive, send_with_id)