"""
API Key & JWT Authentication Middleware
===================================
Validates the X-API-Key header or Authorization Bearer JWT on protected routes.
The key is read from the API_KEY environment variable.
The JWT secret is read from the NEXTAUTH_SECRET or API_KEY environment variable.

Usage (in main.py):
    The global middleware calls verify_api_key_value(key) or verify_jwt(token).
"""

import os
import secrets
import logging
import jwt
from fastapi import Header, HTTPException, status, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("secureforge.api.auth")

# Load the expected key at import time
_API_KEY = os.getenv("API_KEY", "")
_JWT_SECRET = os.getenv("NEXTAUTH_SECRET", _API_KEY)

if not _API_KEY:
    # Auto-generate a key if none is configured
    _API_KEY = secrets.token_hex(32)
    _JWT_SECRET = _API_KEY
    logger.warning(
        "No API_KEY environment variable set. "
        "An auto-generated key is active for this session. "
        "Set API_KEY in your .env file to make this permanent."
    )
else:
    logger.info("API key and JWT authentication enabled.")


def verify_jwt_token(token: str) -> bool:
    """Verify a JWT token using the shared secret."""
    try:
        jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
        return True
    except jwt.PyJWTError as e:
        logger.debug(f"JWT verification failed: {e}")
        return False

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

async def verify_api_key(request: Request) -> None:
    """
    FastAPI dependency.
    Raises 403 if valid JWT or API Key is missing.
    """
    request.state.role = "Operator"

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
            request.state.role = payload.get("role", "Operator")
            return
        except jwt.PyJWTError as e:
            logger.debug(f"JWT verification failed: {e}")

    api_key = request.headers.get("X-API-Key", "")
    if verify_api_key_value(api_key):
        request.state.role = "Administrator"
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing authentication. Pass Authorization Bearer token or X-API-Key.",
    )
