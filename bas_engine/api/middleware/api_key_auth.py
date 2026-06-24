"""
API Key Authentication Middleware
===================================
Validates the X-API-Key header on protected routes.
The key is read from the API_KEY environment variable.

Usage (in main.py):
    The global middleware calls verify_api_key_value(key).
    FastAPI dependency verify_api_key is kept for backward compatibility.
"""

import os
import secrets
import logging
from fastapi import Header, HTTPException, status

logger = logging.getLogger("secureforge.api.auth")

# Load the expected key at import time
_API_KEY = os.getenv("API_KEY", "")

if not _API_KEY:
    # Auto-generate a key if none is configured
    _API_KEY = secrets.token_hex(32)
    logger.warning(
        "No API_KEY environment variable set. "
        "An auto-generated key is active for this session. "
        "Set API_KEY in your .env file to make this permanent."
    )
else:
    logger.info("API key authentication enabled.")


def verify_api_key_value(key: str) -> bool:
    """
    Synchronous helper used by the global HTTP middleware.
    Returns True if the key is valid, False otherwise.
    """
    if not key:
        return False
    try:
        return secrets.compare_digest(str(key), _API_KEY)
    except Exception:
        return False


async def verify_api_key(x_api_key: str = Header(None, alias="X-API-Key")) -> None:
    """
    FastAPI dependency (kept for backward compat).
    Raises 403 if the X-API-Key header is missing or invalid.
    """
    if not verify_api_key_value(x_api_key or ""):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key. Pass X-API-Key header.",
        )
