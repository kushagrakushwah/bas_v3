from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
import os
import secrets
import time
import datetime
import jwt

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

# Simple in-memory rate limit store: {ip: (count, reset_time)}
_LOGIN_ATTEMPTS = {}

@router.post("/login")
async def login(req: LoginRequest, request: Request):
    """
    Very simple backend login endpoint.
    Used by NextAuth in the dashboard to avoid hardcoded frontend credentials.
    In a real production environment, this would query a Users database table.
    """
    # Rate Limiting Logic (5 attempts per minute per IP)
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempts, reset_time = _LOGIN_ATTEMPTS.get(client_ip, (0, 0))
    if now > reset_time:
        attempts = 0
        reset_time = now + 60
    if attempts >= 5:
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")
    
    _LOGIN_ATTEMPTS[client_ip] = (attempts + 1, reset_time)

    # Read secure passwords from environment, fallback to secure random strings if unset
    admin_password = os.getenv("ADMIN_PASSWORD", secrets.token_hex(16))
    operator_password = os.getenv("OPERATOR_PASSWORD", secrets.token_hex(16))
    
    # Retrieve JWT Secret (Do not fallback to API_KEY)
    jwt_secret = os.getenv("NEXTAUTH_SECRET", "")
    if not jwt_secret:
        raise HTTPException(status_code=500, detail="NEXTAUTH_SECRET is not configured on the server.")
    
    def generate_token(username: str, role: str):
        payload = {
            "sub": username,
            "role": role,
            "iat": datetime.datetime.utcnow(),
            "nbf": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        return jwt.encode(payload, jwt_secret, algorithm="HS256")
        
    if req.username == "admin" and secrets.compare_digest(req.password, admin_password):
        token = generate_token("admin", "Administrator")
        # Reset rate limit on success
        _LOGIN_ATTEMPTS[client_ip] = (0, 0)
        return {"status": "success", "token": token, "user": {"id": "1", "name": "admin", "role": "Administrator"}}
        
    if req.username == "operator" and secrets.compare_digest(req.password, operator_password):
        token = generate_token("operator", "Operator")
        _LOGIN_ATTEMPTS[client_ip] = (0, 0)
        return {"status": "success", "token": token, "user": {"id": "2", "name": "operator", "role": "Operator"}}
        
    raise HTTPException(status_code=401, detail="Invalid username or password")
