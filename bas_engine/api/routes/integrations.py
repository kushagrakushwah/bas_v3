from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from bas_engine.database.connection import AsyncSessionLocal
from bas_engine.database.models import IntegrationDB

router = APIRouter()

# Allowed integration types
_ALLOWED_TYPES = {"Slack", "Email", "Webhook", "Splunk", "QRadar", "Generic"}

class IntegrationCreate(BaseModel):
    name: str
    type: str
    target: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("name must be between 1 and 128 characters.")
        return v

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in _ALLOWED_TYPES:
            raise ValueError(f"type must be one of: {', '.join(sorted(_ALLOWED_TYPES))}")
        return v

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """M6 fix: block SSRF payloads in integration target URLs."""
        v = v.strip()
        if not v or len(v) > 2048:
            raise ValueError("target must be between 1 and 2048 characters.")
        
        import urllib.parse
        import socket
        import ipaddress

        parsed = urllib.parse.urlparse(v)
        hostname = parsed.hostname or v
        
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_multicast or 
                ip_obj.is_unspecified):
                raise ValueError(f"Target resolves to a prohibited internal or reserved IP address ({ip_str})")
        except socket.gaierror:
            # If DNS resolution fails, allow it. It will simply fail to connect during runtime.
            pass
            
        return v

@router.get("/")
async def get_integrations():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(IntegrationDB))
        return result.scalars().all()

@router.post("/")
async def create_integration(integration: IntegrationCreate):
    async with AsyncSessionLocal() as session:
        db_integration = IntegrationDB(
            name=integration.name,
            type=integration.type,
            target=integration.target
        )
        session.add(db_integration)
        await session.commit()
        await session.refresh(db_integration)
        return db_integration

@router.delete("/{integration_id}")
async def delete_integration(integration_id: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(IntegrationDB).where(IntegrationDB.id == integration_id))
        db_integration = result.scalar_one_or_none()
        if not db_integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        await session.delete(db_integration)
        await session.commit()
        return {"status": "success"}
