from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import os
import secrets

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
async def login(req: LoginRequest):
    """
    Very simple backend login endpoint.
    Used by NextAuth in the dashboard to avoid hardcoded frontend credentials.
    In a real production environment, this would query a Users database table.
    """
    # Read secure passwords from environment, fallback to secure random strings if unset
    admin_password = os.getenv("ADMIN_PASSWORD", secrets.token_hex(16))
    operator_password = os.getenv("OPERATOR_PASSWORD", secrets.token_hex(16))
    
    # Retrieve JWT Secret
    jwt_secret = os.getenv("NEXTAUTH_SECRET", os.getenv("API_KEY", secrets.token_hex(32)))
    import jwt
    import datetime
    
    def generate_token(username: str, role: str):
        payload = {
            "sub": username,
            "role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        return jwt.encode(payload, jwt_secret, algorithm="HS256")
        
    if req.username == "admin" and secrets.compare_digest(req.password, admin_password):
        token = generate_token("admin", "Administrator")
        return {"status": "success", "token": token, "user": {"id": "1", "name": "admin", "role": "Administrator"}}
        
    if req.username == "operator" and secrets.compare_digest(req.password, operator_password):
        token = generate_token("operator", "Operator")
        return {"status": "success", "token": token, "user": {"id": "2", "name": "operator", "role": "Operator"}}
        
    raise HTTPException(status_code=401, detail="Invalid username or password")
