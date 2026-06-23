"""
API Key Authentication Middleware
===================================
Validates the X-API-Key header on protected routes.
The key is read from the API_KEY environment variable.

Usage (in main.py):
    from bas_engine.api.middleware.api_key_auth import verify_api_key
    app.include_router(simulations.router, dependencies=[Depends(verify_api_key)])
"""

import os
import secrets
import logging
from fastapi import Header, HTTPException, status

logger = logging.getLogger("secureforge.api.auth")

# Load the expected key at import time
_API_KEY = os.getenv("API_KEY", "")

if not _API_KEY:
    # Auto-generate a key if none is configured, and print it clearly
    _API_KEY = secrets.token_hex(32)
    logger.warning(
        "⚠️  No API_KEY environment variable set. "
        f"Using auto-generated key for this session: {_API_KEY}\n"
        "Set API_KEY in docker-compose.yml or your .env file to make this permanent."
    )
else:
    logger.info("API key authentication enabled.")


async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """
    FastAPI dependency. Raises 403 if the X-API-Key header is missing or invalid.
    Exempt routes: /api/v1/health, /ws/*, /
    """
    if not secrets.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key. Pass X-API-Key header.",
        )
